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
import time
from contextlib import contextmanager
from functools import wraps

from django.conf import settings as dj_settings
from django.db import OperationalError, connection, transaction
from django.utils import timezone

from ..models import Run, Settings
from . import hashcat as hc
from . import hashfile

POLL_SECONDS = 10  # send hashcat an 's' keypress this often to refresh status

# A background finaliser MUST land its terminal-status write even if SQLite is briefly
# locked -- a dropped write strands the run in 'running' (an orphan that blocks the
# queue). WAL + busy_timeout (config/settings.py) makes locks rare and self-clearing;
# this is the last-resort retry for the residual case so the state machine never wedges.
SAVE_RETRIES = 6
SAVE_RETRY_SLEEP = 0.5  # seconds between retries (total ~3s on top of the busy timeout)

# A launch reserves the single execution slot by writing status='running' with started_at
# but no pid yet (the pid is registered a moment later, once hashcat is spawned).
# reconcile must not mistake that brief window for a dead/never-launched orphan, so it
# leaves a pid-less 'running' row alone until it is older than this grace.
LAUNCH_GRACE_SECONDS = 60


def _save_run(run, **kwargs):
    """``run.save(**kwargs)`` that rides out a transient SQLite lock.

    Retries on OperationalError ("database is locked") so a finaliser can't leave a
    run stuck in a non-terminal state. Re-raises if it never succeeds."""
    for attempt in range(SAVE_RETRIES):
        try:
            run.save(**kwargs)
            return
        except OperationalError:
            if attempt == SAVE_RETRIES - 1:
                raise
            time.sleep(SAVE_RETRY_SLEEP)

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
# run_ids of orphaned-but-live runs re-adopted after a lost reader thread/restart:
# we can't re-attach hashcat's status stream, so a watcher tails the potfile instead.
_adopted = set()
_lock = threading.Lock()
_lifecycle_lock = threading.RLock()
_workers = {}
DELETE_STOP_SECONDS = 5
DELETE_JOIN_SECONDS = POLL_SECONDS + 5


def _serialize_lifecycle(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        with _lifecycle_lock:
            return fn(*args, **kwargs)
    return wrapped


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


@_serialize_lifecycle
def start_run(run, runner=None):
    """Launch ``run`` with hashcat in a background thread.

    Returns None on success or an error string (guard failure) to show the user.
    """
    runner = runner or hc.configured_runner()
    if not Run.objects.filter(pk=run.pk).exists():
        return 'This attack has been deleted.'
    run.refresh_from_db()
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
    # Reconcile OUTSIDE the transaction: it may adopt a live orphan, which starts a
    # thread. The authoritative one-at-a-time check is the atomic slot claim below.
    reconcile_stale_runs()
    if not _claim_slot(run):
        return BUSY_MESSAGE

    # Slot reserved (status='running', started_at set, pid still None). Prepare files and
    # spawn; ANY failure here must release the slot so a botched launch never strands a
    # 'running' row.
    try:
        workdir = tempfile.mkdtemp(prefix='zebra-run-%d-' % run.pk)
        session = _session_name(run)
        # File-backed: hashcat reads the external file directly (zero-copy) and writes to
        # a *persistent per-project* potfile; this run is credited its delta over the
        # baseline. DB-backed: materialize hashes into a *stable per-run* dir (not the temp
        # workdir), and use a *persistent per-run* potfile (run-<pk>.pot) whose whole
        # contents are this run's cracks -- so no baseline (kept None; recovered = count -
        # (baseline or 0) works for both). The stable hashfile is what ``--restore``
        # re-reads on resume, so it must outlive the disposable workdir (_cleanup_run_files).
        hashpath = run.project.launch_hashfile(_run_hashdir(run))
        if run.project.is_file_backed:
            pot = run.project.resolve_potfile_path()
            run.crack_baseline = hashfile.potfile_cracked_count(pot)
        else:
            pot = os.path.join(dj_settings.ZEBRA_DATA_DIR, 'potfiles', 'run-%d.pot' % run.pk)
            run.crack_baseline = None
        os.makedirs(os.path.dirname(pot), exist_ok=True)
        run.crack_range_end = None  # set at finalisation (stale on a relaunch)
        # Persistent checkpoint so a dead run can be resumed (kept outside workdir).
        restore_path = os.path.join(dj_settings.ZEBRA_DATA_DIR, 'restore', session + '.restore')
        os.makedirs(os.path.dirname(restore_path), exist_ok=True)
        run.session, run.potfile_path, run.restore_path = session, pot, restore_path

        argv = runner.build_run_args(
            3, run.project.hashtype.hashcat_module, hashfile=hashpath,
            params={'mask': run.mask.pattern, 'custom_charsets': run.mask.custom_charsets or {},
                    'increment_min': run.mask.increment_min,
                    'increment_max': run.mask.increment_max},
            extra=['--status', '--status-json', '--status-timer', str(POLL_SECONDS),
                   '--potfile-path', pot, '--session', session,
                   '--restore-file-path', restore_path],
            optimized=run.optimized)

        run.progress = 0.0
        run.recovered = None  # clear any stale value from a prior launch of this run
        run.ended_at = None
        # Seed the increment sweep counter so "(1/N runs)" shows before the first
        # status arrives; hashcat's live guess_base_offset/count refine it as it runs.
        if run.mask and run.mask.is_incremental:
            lo, hi = run.mask.increment_min, run.mask.increment_max
            hi = min(hi, run.mask.length) if hi is not None else run.mask.length
            run.increment_offset = 1  # 1-based, like hashcat's guess_base_offset
            run.increment_count = max(1, hi - lo + 1)
        run.save(update_fields=['progress', 'recovered', 'crack_baseline',
                                'crack_range_end', 'ended_at',
                                'session', 'potfile_path', 'restore_path',
                                'increment_offset', 'increment_count'])
    except Exception as exc:
        _release_slot(run)
        return 'Failed to prepare the launch: %s' % exc
    return _spawn_and_track(run, argv, pot, workdir)


def _claim_slot(run):
    """Atomically reserve the single execution slot for ``run``. Returns True on success.

    Wrapped in ``transaction.atomic()`` so that -- with the IMMEDIATE+WAL SQLite config --
    ``BEGIN`` takes the write lock up front: a concurrent claimer (another thread, or
    another server process on the same DB) blocks here, then sees our 'running' row and
    fails its own check. The reservation writes ``status='running'`` + ``started_at`` but
    leaves ``pid`` None (registered once hashcat is spawned); reconcile's launch grace
    protects that window."""
    with transaction.atomic():
        if Run.objects.filter(status='running').exists():
            return False
        run.status = 'running'
        run.started_at = timezone.now()
        run.pid = None
        _save_run(run, update_fields=['status', 'started_at', 'pid'])
    return True


def _release_slot(run):
    """Release a reserved slot after a failed launch, marking the run 'error'."""
    run.status = 'error'
    run.ended_at = timezone.now()
    run.pid = None
    try:
        _save_run(run, update_fields=['status', 'ended_at', 'pid'])
    except Exception:
        pass  # reconcile will sweep it once the launch grace elapses


def _spawn_and_track(run, argv, pot, workdir):
    """Spawn hashcat under a PTY, register it in ``_active``, start the reader thread.

    Detached (``start_new_session=True``) so the child survives a zebra restart and
    keeps cracking -- recovery re-adopts it via the potfile. Sets ``run.pid`` and
    persists it. Returns None on success, else an error string (workdir cleaned)."""
    try:
        import subprocess
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(argv, cwd=workdir, stdin=slave_fd, stdout=slave_fd,
                                stderr=slave_fd, close_fds=True, start_new_session=True)
        os.close(slave_fd)  # the child holds its own copy
    except OSError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        run.status = 'error'
        run.save(update_fields=['status'])
        return 'Failed to launch hashcat: %s' % exc
    run.pid = proc.pid
    run.save(update_fields=['pid'])
    with _lock:
        _active[run.pk] = proc
    worker = threading.Thread(target=_execute, args=(run, proc, master_fd, workdir, pot),
                              daemon=True)
    with _lock:
        _workers[run.pk] = worker
    worker.start()
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
    finalised = False  # terminal status committed -> a later hiccup must not undo it
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
                # Live progress/speed is a throwaway display update -- a transient DB
                # lock here must not abort an otherwise-healthy run; just skip the tick.
                try:
                    hc.ingest_status(run, live)  # status itself comes from the exit code
                except OperationalError:
                    pass

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
        # Critical write: retry through a transient lock so the run reaches a terminal
        # status. Once it lands, the run is finalised -- later steps must not clobber it.
        _save_run(run, update_fields=fields)
        finalised = True

        # Post-finalise bookkeeping (crack import + recovery-file cleanup). A failure
        # here (e.g. a lock during ingest, a cleanup error) must NOT reopen the
        # already-committed terminal status, so it is guarded on its own.
        try:
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
            # Drop recovery files ONLY on a terminal finalize (exhausted/cracked):
            # the search is complete, so the checkpoint/hashfile are spent. An
            # aborted/error run stays resumable, so keep them for resume_run
            # (reconcile/delete clean them if the run is later abandoned).
            if run.status in TERMINAL_STATUSES:
                _cleanup_run_files(run, drop_potfile=not run.project.is_file_backed)
        except Exception as exc:
            run.comment = ('%s | post-finalise warning: %s' % (run.comment or '', exc))[:1000]
            try:
                _save_run(run, update_fields=['comment'])
            except Exception:
                pass  # best-effort note; the terminal status already stuck
    except Exception as exc:  # never let the thread die silently
        # Only downgrade to 'error' if we never committed a terminal status; otherwise
        # a finished run stays finished. A dropped write here leaves the run 'running',
        # but its process is gone, so reconcile_stale_runs sweeps it on the next tick.
        if not finalised:
            run.status = 'error'
            run.ended_at = timezone.now()
            run.pid = None
            run.comment = ('%s | launch error: %s' % (run.comment or '', exc))[:1000]
            try:
                _save_run(run, update_fields=['status', 'ended_at', 'pid', 'comment'])
            except Exception:
                pass
    finally:
        stop_poll.set()
        try:
            os.close(fd)
        except OSError:
            pass
        with _lock:
            _active.pop(run.pk, None)
        shutil.rmtree(workdir, ignore_errors=True)
        connection.close()
        with _lock:
            _workers.pop(run.pk, None)
        # This run's status is already terminal, so the one-at-a-time guard is now
        # clear: chain to the next queued attack (unless the queue is paused).
        _advance_queue()
        connection.close()


def _run_hashdir(run):
    """Stable per-run directory holding a DB-backed run's materialized hashfile.

    Kept outside the disposable temp workdir so ``hashcat --restore`` can re-read the
    hashes on resume; removed by ``_cleanup_run_files`` once the run is no longer
    resumable (terminal completion or delete)."""
    return os.path.join(dj_settings.ZEBRA_DATA_DIR, 'hashfiles', 'run-%d' % run.pk)


def _cleanup_run_files(run, drop_potfile):
    """Best-effort removal of a run's recovery files: its checkpoint, per-run potfile,
    and materialized hashfile dir.

    Only called once a run is no longer resumable -- a clean terminal finalize
    (exhausted/cracked) or an explicit delete -- so an aborted/error run keeps these
    for ``resume_run``. Never removes a file-backed project's *shared* potfile
    (``drop_potfile`` is False there) or its external hashfile."""
    paths = [run.restore_path] if run.restore_path else []
    if drop_potfile and run.potfile_path:
        paths.append(run.potfile_path)
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass
    # DB-backed only: the per-run materialized hashfile dir (file-backed references an
    # external file we must never delete).
    if run.project_id and not run.project.is_file_backed:
        shutil.rmtree(_run_hashdir(run), ignore_errors=True)


def _pid_is_hashcat(pid, session=None):
    """Best-effort check that ``pid`` is a live hashcat process (Linux /proc).

    Guards the recovery paths from signalling/adopting an unrelated process that has
    since reused the recorded pid. When ``session`` is given, its ``--session`` name
    must also appear in the cmdline, so we only ever adopt THIS run's hashcat (not a
    different run's). Returns False if the pid is gone, not ours, or /proc is
    unreadable (non-Linux)."""
    if not pid:
        return False
    try:
        with open('/proc/%d/cmdline' % pid, 'rb') as f:
            cmdline = f.read()
    except OSError:
        return False
    if b'hashcat' not in cmdline:
        return False
    return session is None or session.encode() in cmdline


def _run_is_live(run):
    """True if a ``running`` row is actually backed by a live process.

    Either this process launched it (it's in ``_active``) or its recorded pid is a
    live hashcat process. A ``running`` row that is neither is *orphaned*: its
    worker thread was lost to a server restart, or it was never really launched
    (e.g. a stale row from a crash, which has no pid at all)."""
    if run.pk in _active or run.pk in _adopted:
        return True
    return bool(run.pid) and _pid_is_hashcat(run.pid, run.session or None)


@_serialize_lifecycle
def reconcile_stale_runs():
    """Reconcile orphaned ``running`` rows so the launcher self-heals.

    An orphan is a ``running`` row this process isn't tracking (a server restart, a
    lost reader thread, or a stale row that never really launched). For each:

    * **still-live** (its pid is our hashcat, by session) -> **adopt** it: a watcher
      resumes crack tracking from the potfile (see ``_adopt``). It stays ``running``,
      so the one-at-a-time guard still blocks new launches.
    * **dead** -> mark ``aborted`` (as before). Its restore checkpoint, if any, stays
      on disk so it can be resumed. This clears the guard.

    Serialised on the lifecycle lock so it can't observe (and wrongly abort) a run in
    ``start_run``'s status->pid registration window. Per-row failures are isolated and
    the abort write is retried, so one locked row can't wedge the whole sweep.

    Returns the number of dead orphans aborted."""
    aborted = 0
    now = timezone.now()
    for run in Run.objects.filter(status='running'):
        if run.pk in _active or run.pk in _adopted:
            continue  # already tracked by this process
        if run.potfile_path and run.pid and _pid_is_hashcat(run.pid, run.session or None):
            _adopt(run)  # live orphan -> tail its potfile
            continue
        # Launch grace: a freshly-reserved slot is 'running' with no pid yet (this or
        # another process is mid-launch). Leave it until it ages out of the grace, so a
        # concurrent reconcile can't abort a launch in progress.
        if run.pid is None and run.started_at \
                and (now - run.started_at).total_seconds() < LAUNCH_GRACE_SECONDS:
            continue
        run.status = 'aborted'
        run.pid = None
        run.ended_at = timezone.now()
        try:
            _save_run(run, update_fields=['status', 'pid', 'ended_at'])
        except OperationalError:
            continue  # still locked after retries; next tick will sweep it
        aborted += 1
    return aborted


def recover_orphans():
    """Startup entry point: reconcile/adopt any orphaned runs (see reconcile)."""
    return reconcile_stale_runs()


def adopt_live_orphans():
    """Adopt live orphaned runs *without* aborting dead ones -- safe on a GET.

    Starts a potfile watcher for any 'running' row backed by a live hashcat we
    aren't tracking (thread lost without a restart). It never mutates a dead/stale
    row (that's reconcile_stale_runs' job, on the action paths), so calling it on a
    page render can't wrongly abort a run."""
    for run in Run.objects.filter(status='running'):
        if run.pk in _active or run.pk in _adopted:
            continue
        if run.potfile_path and run.pid and _pid_is_hashcat(run.pid, run.session or None):
            _adopt(run)


def recover_and_advance():
    """Lazy self-heal for page views: sweep orphaned runs and keep the queue moving.

    Adopting a live orphan and aborting a dead one now that ``reconcile_stale_runs`` is
    lifecycle-serialised (so it can't race a starting run), then advancing the queue.
    Without this a run stranded in ``running`` -- e.g. by a transient DB lock during
    finalisation -- would block the one-at-a-time guard, and thus the queue and
    autopilot, until an explicit launch/stop action happened to reconcile it. Reconcile
    runs unconditionally (so a dead orphan is cleared even when the queue is off);
    ``_advance_queue`` then starts the next run only if the queue is on/auto and idle.
    Best-effort and side-effect-light: it writes nothing unless there is an orphan to
    sweep or a run to start, and never raises into request handling."""
    try:
        reconcile_stale_runs()
        _advance_queue()
    except Exception:
        pass


@_serialize_lifecycle
def _adopt(run):
    """Start a watcher that recovers a live orphaned run via its potfile.

    hashcat's status stream can't be re-attached, but because only one hashcat runs
    at a time, potfile growth is unambiguously this run's cracks. The watcher tails
    the potfile for the live crack count and finalises when the pid disappears."""
    if not Run.objects.filter(pk=run.pk).exists():
        return
    with _lock:
        if run.pk in _active or run.pk in _adopted:
            return
        _adopted.add(run.pk)
        worker = threading.Thread(target=_adopt_watch, args=(run,), daemon=True)
        _workers[run.pk] = worker
    worker.start()


def _adopt_potfile_count(run):
    """This run's crack count from its potfile (delta over baseline for file-backed)."""
    return max(0, hashfile.potfile_cracked_count(run.potfile_path) - (run.crack_baseline or 0))


def _adopt_tick(run):
    """One watcher pass: refresh the live crack count from the potfile.

    For DB-backed, also import any new potfile lines into Crack rows (idempotent)."""
    run.recovered = _adopt_potfile_count(run)
    run.save(update_fields=['recovered'])
    if not run.project.is_file_backed:
        try:
            with open(run.potfile_path, encoding='utf-8') as f:
                pairs = hc.parse_potfile(f.read())
            if pairs:
                hc.ingest_cracks(run.project, pairs, run)
        except FileNotFoundError:
            pass


def _adopt_finalize(run):
    """Finalise an adopted run once its process is gone (no exit code available).

    We can't confirm exhaustion without the stream, so this is ``aborted`` + a note
    -- except when every targeted hash was recovered, which we can safely call
    ``cracked``. Crack tracking is pinned from the potfile."""
    _adopt_tick(run)  # final crack count
    count = hashfile.potfile_cracked_count(run.potfile_path)
    run.recovered = max(0, count - (run.crack_baseline or 0))
    run.crack_range_end = count if run.project.is_file_backed else run.crack_range_end
    run.ended_at = timezone.now()
    run.pid = None
    if run.recovered and run.recovered >= run.target_count():
        run.status = 'cracked'
    else:
        run.status = 'aborted'
        run.comment = ('%s | recovered via potfile after lost contact; '
                       'progress/exhaustion unknown' % (run.comment or '')).strip(' |')[:1000]
    run.save(update_fields=['status', 'recovered', 'crack_range_end', 'ended_at',
                            'pid', 'comment'])


def _adopt_watch(run):
    """Watcher thread: tail the potfile until the process exits, then finalise."""
    import time
    try:
        while _pid_is_hashcat(run.pid, run.session or None):
            time.sleep(POLL_SECONDS)
            try:
                _adopt_tick(run)
            except Exception:
                pass  # a transient error mustn't kill the watcher
        _adopt_finalize(run)
    finally:
        connection.close()
        with _lock:
            _adopted.discard(run.pk)
            _workers.pop(run.pk, None)
        _advance_queue()
        connection.close()


def _signal_and_wait_exit(run):
    """SIGINT an orphaned hashcat (by session), wait for exit, escalate to SIGKILL.

    Confirms the process is actually gone before the caller releases the execution
    slot, so a stopped orphan can't run concurrently with the next attack. Each signal
    is re-guarded by ``_pid_is_hashcat`` (session-checked) so a pid reused by an
    unrelated process is never hit."""
    def alive():
        return _pid_is_hashcat(run.pid, run.session or None)
    for sig in (signal.SIGINT, signal.SIGKILL):
        if not alive():
            return
        try:
            os.kill(run.pid, sig)
        except OSError:
            return  # gone between the check and the signal
        deadline = time.monotonic() + DELETE_STOP_SECONDS
        while alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not alive():
            return


def stop_run(run):
    """Stop a running attack, or recover an orphaned one.

    * **Tracked by this process** (its process is in ``_active``): SIGINT it and let the
      reader thread record the final status -- SIGINT is hashcat's checkpoint-abort.
    * **Adopted** (a ``_adopt_watch`` watcher is tailing it): SIGINT the process and let
      the watcher finalise on real pid death. The slot stays ``running`` until exit.
    * **Truly orphaned** (no tracker; e.g. a server restart): SIGINT the surviving
      hashcat *by session*, wait for it to exit (escalating to SIGKILL), and only then
      mark it ``aborted`` -- so no second attack can start while it is still running.
    """
    with _lock:
        proc = _active.get(run.pk)
        adopted = run.pk in _adopted
    if proc is not None:
        try:
            proc.send_signal(signal.SIGINT)
        except (ProcessLookupError, OSError) as exc:
            return 'Could not stop the process: %s' % exc
        return None  # _execute finalises on exit

    if adopted:
        # A watcher is tailing this run; signal the process and let it finalise the run
        # when the pid disappears (keeps the slot held until real exit).
        if run.pid and _pid_is_hashcat(run.pid, run.session or None):
            try:
                os.kill(run.pid, signal.SIGINT)
            except OSError:
                pass
        return None

    # Truly orphaned: nothing is tracking it. Confirm the process is gone before we
    # release the slot by marking the run aborted.
    if run.pid and _pid_is_hashcat(run.pid, run.session or None):
        _signal_and_wait_exit(run)
    if run.status == 'running':
        run.status = 'aborted'
        run.pid = None
        run.ended_at = timezone.now()
        _save_run(run, update_fields=['status', 'pid', 'ended_at'])
    return None


@_serialize_lifecycle
def resume_run(run, runner=None):
    """Resume a dead run from its hashcat checkpoint. Returns None or an error string.

    Relaunches ``hashcat --session <name> --restore``: hashcat replays the original
    command line (potfile + status flags) from the restore file, so crack attribution
    continues and full live streaming comes back via the normal ``_execute`` path
    (real exit code -> correct exhausted/cracked finalise). Guarded so it never runs
    while the process is still alive or another attack is running."""
    runner = runner or hc.configured_runner()
    if not Run.objects.filter(pk=run.pk).exists():
        return 'This attack has been deleted.'
    run.refresh_from_db()
    if not runner.available():
        return 'hashcat is not installed on this machine.'
    if not run.recovery_ready():
        return 'No checkpoint to resume from.'
    if _pid_is_hashcat(run.pid, run.session or None):
        return 'This attack is still running.'
    reconcile_stale_runs()  # may adopt a live orphan; the real guard is the atomic claim
    if not _claim_slot(run):  # atomically reserve the single execution slot
        return BUSY_MESSAGE
    try:
        workdir = tempfile.mkdtemp(prefix='zebra-resume-%d-' % run.pk)
        argv = [runner.binary, '--session', run.session, '--restore',
                '--restore-file-path', run.restore_path]
        run.ended_at = None
        run.crack_range_end = None
        run.save(update_fields=['ended_at', 'crack_range_end'])
    except Exception as exc:
        _release_slot(run)
        return 'Failed to prepare the resume: %s' % exc
    return _spawn_and_track(run, argv, run.potfile_path, workdir)


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
    # Finalizers must never wait for a deletion which is joining their thread.
    # The deletion retries queue advancement after releasing the lifecycle lock.
    if not _lifecycle_lock.acquire(blocking=False):
        return None
    try:
        return _advance_queue_unlocked(runner)
    finally:
        _lifecycle_lock.release()


def _advance_queue_unlocked(runner=None):
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


@contextmanager
def deleting_runs(runs):
    """Quiesce processes and readers before the caller deletes rows/files.

    Yields an error on failure: the caller must then retain the records/files.
    Launches and queue advancement are excluded until deletion finishes.
    """
    success = False
    with _lifecycle_lock:
        error = None
        targets = []
        groups = {}
        with _lock:
            for run in runs:
                targets.append((run, _active.get(run.pk), _workers.get(run.pk)))

        def leader_live(run, proc):
            if proc is not None:
                return proc.poll() is None
            return _pid_is_hashcat(run.pid, run.session or None)

        def live(run, proc):
            alive = leader_live(run, proc)  # poll also reaps our child
            group = groups.get(run.pk)
            return alive or (group is not None and _process_group_live(group))

        def send(run, proc, sig):
            group = groups.get(run.pk)
            if group is not None:
                os.killpg(group, sig)
            elif leader_live(run, proc):
                pid = proc.pid if proc is not None else run.pid
                os.kill(pid, sig)

        try:
            for run, proc, _ in targets:
                if leader_live(run, proc):
                    pid = proc.pid if proc is not None else run.pid
                    try:
                        if os.getpgid(pid) == pid:
                            groups[run.pk] = pid
                    except ProcessLookupError:
                        pass
            for run, proc, _ in targets:
                try:
                    send(run, proc, signal.SIGINT)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + DELETE_STOP_SECONDS
            while any(live(r, p) for r, p, _ in targets) and time.monotonic() < deadline:
                time.sleep(0.05)
            for run, proc, _ in targets:
                try:
                    send(run, proc, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + DELETE_STOP_SECONDS
            while any(live(r, p) for r, p, _ in targets) and time.monotonic() < deadline:
                time.sleep(0.05)
            if any(live(r, p) for r, p, _ in targets):
                error = 'Could not stop all attack processes; nothing was deleted.'
            else:
                for _, _, worker in targets:
                    if worker is not None:
                        worker.join(DELETE_JOIN_SECONDS)
                        if worker.is_alive():
                            error = 'Attack finalization is still running; retry deletion.'
                            break
        except OSError as exc:
            error = 'Could not stop attack processes; nothing was deleted: %s' % exc
        yield error
        success = error is None
    if success:
        _advance_queue()


def _process_group_live(pgid):
    """Whether a Linux process group contains any non-zombie processes."""
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                with open(os.path.join(entry.path, 'stat')) as f:
                    # comm can contain spaces and parentheses; fields after it
                    # begin with state, ppid, pgrp.
                    fields = f.read().rsplit(')', 1)[1].split()
                if int(fields[2]) == pgid and fields[0] not in ('Z', 'X'):
                    return True
            except (FileNotFoundError, ProcessLookupError):
                continue
    return False


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
