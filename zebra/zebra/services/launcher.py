"""Active launcher: run a recorded mask attack with hashcat, in the background.

First cut (see plan): **mask attacks only** (they need no external files), executed
in a **daemon thread** so the web request returns immediately while the page polls
for progress. Reuses services.hashcat for command building, status parsing, and
crack ingest.

hashcat is run under a **pseudo-terminal**: on a plain pipe it block-buffers and
never sees the ``s`` keypress, so status only arrives at the very end. A PTY makes it
behave interactively (prompt flushing + honoring ``--status-timer``), and lets us
send an ``s`` keypress every ``POLL_SECONDS`` to poll status on demand.

Limitations (by design for a local single-operator tool):
- One run at a time (the GPU is exclusive).
- A server restart orphans a running run (left ``running``); recover with Stop.
- The command is executed from an argv **list**, never a shell string.
- POSIX only (uses ``pty``).
"""

import os
import pty
import re
import shutil
import signal
import tempfile
import threading

from django.db import connection
from django.utils import timezone

from ..models import Run, Settings
from . import hashcat as hc
from . import hashfile

POLL_SECONDS = 10  # send hashcat an 's' keypress this often to refresh status

# Finished run states: the search is complete (whole keyspace exhausted, or all
# targeted hashes cracked), so there is nothing left to (re)launch or queue.
TERMINAL_STATUSES = ('exhausted', 'cracked')

# start_run's one-at-a-time refusal, as a constant so run_or_queue can recognise a
# lost race and fall back to queueing.
BUSY_MESSAGE = 'Another attack is already running (one at a time).'


def _session_name(run):
    """Filesystem-safe hashcat ``--session`` name identifying this run.

    Always starts with ``zebra`` and carries the project number + a slug of its
    name and the attack (run) number, e.g. ``zebra-p3-ad-dump-2024-a17``, so
    hashcat's restore/session files are recognisable and don't collide.
    """
    parts = ['zebra']
    if run.project_id:
        parts.append('p%d' % run.project_id)
        slug = re.sub(r'[^a-z0-9]+', '-', (run.project.name or '').lower()).strip('-')
        if slug:
            parts.append(slug[:24])
    parts.append('a%d' % run.pk)
    return '-'.join(parts)


# run_id -> subprocess.Popen for the currently-running attack(s).
_active = {}
_lock = threading.Lock()


def _iter_lines(fd):
    """Yield decoded lines read from a fd, splitting on \\n and \\r.

    Works for both a PTY master (raises OSError/EIO at child exit) and a pipe
    (returns b'' at EOF)."""
    buf = b''
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break  # PTY slave closed
        if not chunk:
            break
        buf += chunk
        while True:
            positions = [i for i in (buf.find(b'\n'), buf.find(b'\r')) if i != -1]
            if not positions:
                break
            cut = min(positions)
            line, buf = buf[:cut], buf[cut + 1:]
            yield line.decode('utf-8', 'ignore')
    if buf:
        yield buf.decode('utf-8', 'ignore')


def _final_status(returncode):
    """Map a hashcat exit code to a Run status.

    0 cracked · 1 exhausted · 2/3/4 aborted (user/checkpoint/runtime) · else error.
    A death by SIGINT/SIGTERM (negative code, e.g. our Stop) counts as aborted.
    """
    if returncode in (-signal.SIGINT, -signal.SIGTERM):
        return 'aborted'
    return {0: 'cracked', 1: 'exhausted',
            2: 'aborted', 3: 'aborted', 4: 'aborted'}.get(returncode, 'error')


def start_run(run, runner=None):
    """Launch ``run`` with hashcat in a background thread.

    Returns None on success or an error string (guard failure) to show the user.
    """
    runner = runner or hc.configured_runner()
    if not runner.available():
        return 'hashcat is not installed on this machine.'
    if run.attack_mode != 3:
        return 'Only mask attacks (-a 3) can be launched yet.'
    if run.mask is None:
        return 'This mask attack has no mask to run.'
    if run.status in TERMINAL_STATUSES:
        return 'This attack is already %s — nothing left to run.' % run.status
    if run.project is None:
        return 'This project has no hashes to attack.'
    if not run.project.has_hashes():
        if run.project.is_file_backed:
            return 'Hash file not found or empty: %s' % run.project.hashfile_path
        return 'This project has no hashes to attack.'
    if run.project.hashtype is None:
        return 'This project has no hash type set.'
    with _lock:
        reconcile_stale_runs()  # self-heal orphaned 'running' rows before the guard
        if Run.objects.filter(status='running').exists():
            return BUSY_MESSAGE

    workdir = tempfile.mkdtemp(prefix='zebra-run-%d-' % run.pk)
    # File-backed: hashcat reads the external file directly (zero-copy) and writes
    # to a *persistent* per-project potfile (kept outside workdir, so it survives
    # this run's cleanup and lets hashcat auto-skip already-cracked hashes next
    # time). DB-backed: materialize hashes into workdir and use a transient potfile.
    hashpath = run.project.launch_hashfile(workdir)
    if run.project.is_file_backed:
        pot = run.project.resolve_potfile_path()
        os.makedirs(os.path.dirname(pot), exist_ok=True)
        # Baseline = cracks already in the shared potfile before this run, so this
        # run is credited only with what IT finds (recovered - crack_baseline).
        run.crack_baseline = hashfile.potfile_cracked_count(pot)
    else:
        pot = os.path.join(workdir, 'zebra.pot')
        run.crack_baseline = None
    run.crack_range_end = None  # set at finalisation (stale on a relaunch)

    argv = runner.build_run_args(
        3, run.project.hashtype.hashcat_module, hashfile=hashpath,
        params={'mask': run.mask.pattern, 'custom_charsets': run.mask.custom_charsets or {},
                'increment_min': run.mask.increment_min,
                'increment_max': run.mask.increment_max},
        extra=['--status', '--status-json', '--status-timer', str(POLL_SECONDS),
               '--potfile-path', pot, '--restore-disable',
               '--session', _session_name(run)],
        optimized=run.optimized)

    # Run under a PTY so hashcat flushes status promptly and accepts 's' keypresses.
    try:
        import subprocess
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(argv, cwd=workdir, stdin=slave_fd, stdout=slave_fd,
                                stderr=slave_fd, close_fds=True)
        os.close(slave_fd)  # the child holds its own copy
    except OSError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        return 'Failed to launch hashcat: %s' % exc

    run.status = 'running'
    run.progress = 0.0
    run.recovered = None  # clear any stale value from a prior launch of this run
    run.started_at = timezone.now()
    run.ended_at = None
    run.pid = proc.pid
    # Seed the increment sweep counter so "(1/N runs)" shows before the first
    # status arrives; hashcat's live guess_base_offset/count refine it as it runs.
    if run.mask and run.mask.is_incremental:
        lo, hi = run.mask.increment_min, run.mask.increment_max
        hi = min(hi, run.mask.length) if hi is not None else run.mask.length
        run.increment_offset = 1  # 1-based, like hashcat's guess_base_offset
        run.increment_count = max(1, hi - lo + 1)
    run.save(update_fields=['status', 'progress', 'recovered', 'crack_baseline',
                            'crack_range_end', 'started_at', 'ended_at', 'pid',
                            'increment_offset', 'increment_count'])
    with _lock:
        _active[run.pk] = proc
    threading.Thread(target=_execute, args=(run, proc, master_fd, workdir, pot),
                     daemon=True).start()
    return None


def _execute(run, proc, fd, workdir, pot):
    """Stream hashcat output (read from ``fd``) into ``run`` and finalise it.

    Synchronous (the thread target); called directly by tests to avoid cross-thread
    DB issues. A side poller sends 's' every POLL_SECONDS to refresh the status."""
    stop_poll = threading.Event()

    def _poll():
        while not stop_poll.wait(POLL_SECONDS):
            if proc.poll() is not None:
                break
            try:
                os.write(fd, b's')  # hashcat: 's' -> print status now
            except OSError:
                break

    threading.Thread(target=_poll, daemon=True).start()
    try:
        for line in _iter_lines(fd):
            line = line.strip()
            if not line.startswith('{'):
                continue  # ignore hashcat's banner / interactive UI chatter
            try:
                summary = hc.parse_status_json(line)
            except ValueError:
                continue
            live = {k: v for k, v in summary.items()
                    if k in ('progress', 'speed_hs', 'recovered',
                             'base_offset', 'base_count')}
            if live:
                hc.ingest_status(run, live)  # progress/speed only; status from exit code

        code = proc.wait()
        run.status = _final_status(code)
        run.ended_at = timezone.now()
        run.pid = None
        if run.status == 'exhausted':
            run.progress = 1.0
        fields = ['status', 'ended_at', 'pid', 'progress']
        # File-backed: pin recovered to the final potfile count and record the end
        # of this run's crack range. One-at-a-time execution + an append-only
        # potfile means the run's cracks are exactly rows [crack_baseline,
        # crack_range_end), so this pinpoints which recovered hashes it found.
        if run.project.is_file_backed:
            final = hashfile.potfile_cracked_count(pot)
            run.recovered = final
            run.crack_range_end = final
            fields += ['recovered', 'crack_range_end']
        run.save(update_fields=fields)

        # DB-backed: import the run's potfile into Crack rows + the cracked flag.
        # File-backed: the persistent potfile IS the source of truth (no Crack
        # rows), so there is nothing to ingest.
        if not run.project.is_file_backed:
            try:
                with open(pot, encoding='utf-8') as f:
                    pairs = hc.parse_potfile(f.read())
                if pairs:
                    hc.ingest_cracks(run.project, pairs, run)
            except FileNotFoundError:
                pass
    except Exception as exc:  # never let the thread die silently
        run.status = 'error'
        run.ended_at = timezone.now()
        run.pid = None
        run.comment = ('%s | launch error: %s' % (run.comment or '', exc))[:1000]
        run.save(update_fields=['status', 'ended_at', 'pid', 'comment'])
    finally:
        stop_poll.set()
        try:
            os.close(fd)
        except OSError:
            pass
        with _lock:
            _active.pop(run.pk, None)
        shutil.rmtree(workdir, ignore_errors=True)
        # This run's status is already terminal, so the one-at-a-time guard is now
        # clear: chain to the next queued attack (unless the queue is paused).
        _advance_queue()
        connection.close()


def _pid_is_hashcat(pid):
    """Best-effort check that ``pid`` is a live hashcat process (Linux /proc).

    Guards the orphan-recovery path from signalling an unrelated process that has
    since reused the recorded pid. Returns False if the pid is gone, not ours, or
    /proc is unreadable (non-Linux)."""
    try:
        with open('/proc/%d/cmdline' % pid, 'rb') as f:
            return b'hashcat' in f.read()
    except OSError:
        return False


def _run_is_live(run):
    """True if a ``running`` row is actually backed by a live process.

    Either this process launched it (it's in ``_active``) or its recorded pid is a
    live hashcat process. A ``running`` row that is neither is *orphaned*: its
    worker thread was lost to a server restart, or it was never really launched
    (e.g. a stale row from a crash, which has no pid at all)."""
    if run.pk in _active:
        return True
    return bool(run.pid) and _pid_is_hashcat(run.pid)


def reconcile_stale_runs():
    """Abort orphaned ``running`` rows so they stop deadlocking the launcher.

    The one-at-a-time guard treats *any* ``running`` row as the active attack, so a
    single orphan (a restart, a crash, or a row that never really launched) blocks
    every future launch with "another attack is already running" -- with no obvious
    Stop button to clear it. Sweeping orphans to ``aborted`` here, lazily, right
    before the guard is checked, makes the state machine self-healing. Returns the
    number of runs reconciled."""
    reconciled = 0
    for run in Run.objects.filter(status='running'):
        if _run_is_live(run):
            continue
        run.status = 'aborted'
        run.pid = None
        run.ended_at = timezone.now()
        run.save(update_fields=['status', 'pid', 'ended_at'])
        reconciled += 1
    return reconciled


def stop_run(run):
    """Stop a running attack, or recover an orphaned one.

    If a worker thread is actively managing the run (its process is in ``_active``),
    SIGINT it and let the thread record the final status -- SIGINT is hashcat's
    clean checkpoint-abort.

    Otherwise the run is *orphaned*: its thread is gone (typically a server
    restart), so nothing will ever move it out of ``running`` and it keeps blocking
    new launches. We SIGINT any surviving hashcat pid (best effort), then mark the
    run ``aborted`` here so the state machine is unstuck.
    """
    with _lock:
        proc = _active.get(run.pk)
    if proc is not None:
        try:
            proc.send_signal(signal.SIGINT)
        except (ProcessLookupError, OSError) as exc:
            return 'Could not stop the process: %s' % exc
        return None

    # Orphaned run: no live thread is tracking it.
    if run.pid and _pid_is_hashcat(run.pid):
        try:
            os.kill(run.pid, signal.SIGINT)
        except OSError:
            pass  # died between the check and the signal -- fine, we abort below
    if run.status == 'running':
        run.status = 'aborted'
        run.pid = None
        run.ended_at = timezone.now()
        run.save(update_fields=['status', 'pid', 'ended_at'])
    return None


# --- attack queue -----------------------------------------------------------
#
# A machine-wide FIFO (reorderable) queue of mask runs. Enqueuing marks a planned
# run 'queued'; when the active run finalises (or on enqueue/resume while idle) the
# lowest-position queued run is auto-started. The GPU is a single resource, so the
# queue spans all projects and honours the same one-at-a-time guarantee.

def queue_mode():
    """The persisted queue master switch: 'off', 'on', or 'auto'."""
    return Settings.load().queue_mode


def is_paused():
    """Whether the queue won't auto-start anything (master switch 'off')."""
    return queue_mode() == 'off'


def is_auto():
    """Whether auto-pilot is on: keep the queue full with suggested attacks."""
    return queue_mode() == 'auto'


def set_queue_mode(mode):
    """Set the persisted queue master switch ('off'/'on'/'auto'), no side effects."""
    if mode not in ('off', 'on', 'auto'):
        raise ValueError('bad queue mode: %r' % mode)
    s = Settings.load()
    if s.queue_mode != mode:
        s.queue_mode = mode
        s.save(update_fields=['queue_mode'])


def set_queue_paused(paused):
    """Back-compat two-state setter: off when paused, else on."""
    set_queue_mode('off' if paused else 'on')


def _next_queued():
    """The queued run that should run next (lowest position), or None."""
    return (Run.objects.filter(status='queued')
            .order_by('queue_position', 'pk').first())


def _advance_queue(runner=None):
    """Start the next queued run if the queue is active and nothing is running.

    Relies on ``start_run``'s DB guard as the real gate, so it does not hold
    ``_lock`` across the call (Lock is not reentrant). Returns the started run or
    None."""
    if is_paused():
        return None
    reconcile_stale_runs()  # don't let an orphan block the queue either
    if Run.objects.filter(status='running').exists():
        return None
    nxt = _next_queued()
    if nxt is None and is_auto():
        nxt = _fill_auto()  # queue empty + auto-pilot: create a fresh suggested run
    if nxt is None:
        return None
    err = start_run(nxt, runner=runner)
    return None if err else nxt


def _fill_auto():
    """Create a queued auto-pilot run (a fresh suggested attack), or None.

    Only when hashcat is available -- an auto task is worthless if it can't launch.
    The run is marked 'queued' so a failed start leaves it in the queue (the next
    advance retries it) rather than spawning another."""
    if not hc.configured_runner().available():
        return None
    from .. import autopilot
    run = autopilot.next_auto_run()
    if run is None:
        return None
    last = (Run.objects.filter(status='queued')
            .order_by('-queue_position').first())
    run.queue_position = (last.queue_position + 1) if last and last.queue_position else 1
    run.status = 'queued'
    run.save(update_fields=['status', 'queue_position'])
    return run


def would_queue():
    """True if launching now would queue rather than start immediately.

    That's when a run is already in progress, or the queue is paused (so an
    auto-start won't happen). A pure read (no DB writes -- it's called on plain
    page renders) used only to label the run/queue buttons; ``run_or_queue`` does
    the authoritative check (with orphan reconciliation) when the action fires, so
    a stale label self-corrects on the next request."""
    return is_paused() or Run.objects.filter(status='running').exists()


def run_or_queue(run):
    """Start ``run`` now if the GPU is idle, otherwise add it to the queue.

    The single "run" action used everywhere: it runs when nothing else is, and
    queues when a job is in progress (or the queue is paused). Returns
    ``(action, error)`` where action is 'started', 'queued', or 'error'. Real
    problems (no hashcat, no hashes, ...) surface as ('error', msg); only a busy
    GPU falls through to queueing."""
    if not would_queue():
        err = start_run(run)
        if err is None:
            return ('started', None)
        if err != BUSY_MESSAGE:
            return ('error', err)  # a genuine problem, not just "busy"
        # Lost a race (someone started between the check and start_run) -> queue.
    return ('queued', enqueue(run))


def enqueue(run):
    """Add a planned mask run to the tail of the queue; start it if idle.

    Returns None on success or an error string."""
    if run.attack_mode != 3:
        return 'Only mask attacks (-a 3) can be queued yet.'
    if run.mask is None:
        return 'This mask attack has no mask to run.'
    if run.status in TERMINAL_STATUSES:
        return 'This attack is already %s — nothing left to queue.' % run.status
    if run.status in ('running', 'queued'):
        return None  # already active/queued -- nothing to do
    last = (Run.objects.filter(status='queued')
            .order_by('-queue_position').first())
    run.queue_position = (last.queue_position + 1) if last and last.queue_position else 1
    run.status = 'queued'
    run.save(update_fields=['status', 'queue_position'])
    _advance_queue()
    return None


def dequeue(run):
    """Remove a run from the queue, returning it to 'planned'."""
    if run.status == 'queued':
        run.status = 'planned'
        run.queue_position = None
        run.save(update_fields=['status', 'queue_position'])
    return None


def move(run, delta):
    """Reorder a queued run by swapping positions with its neighbour (delta ±1)."""
    if run.status != 'queued':
        return None
    order = list(Run.objects.filter(status='queued').order_by('queue_position', 'pk'))
    idx = next((i for i, r in enumerate(order) if r.pk == run.pk), None)
    if idx is None:
        return None
    swap = idx + (1 if delta > 0 else -1)
    if 0 <= swap < len(order):
        a, b = order[idx], order[swap]
        a.queue_position, b.queue_position = b.queue_position, a.queue_position
        # positions may be null/duplicated on legacy rows -> normalise this pair
        if a.queue_position == b.queue_position:
            a.queue_position, b.queue_position = swap + 1, idx + 1
        a.save(update_fields=['queue_position'])
        b.save(update_fields=['queue_position'])
    return None


def pause_queue():
    """Turn the queue off: stop auto-advancing (the active run keeps going)."""
    set_queue_paused(True)


def resume_queue():
    """Turn the queue on: resume auto-advance and start the next run if idle."""
    set_queue_paused(False)
    _advance_queue()
