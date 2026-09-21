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
import shutil
import signal
import tempfile
import threading

from django.db import connection
from django.utils import timezone

from ..models import Run
from . import hashcat as hc

POLL_SECONDS = 10  # send hashcat an 's' keypress this often to refresh status

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


def _materialize_hashfile(project, path):
    """Write the project's hash strings, one per line, to ``path``."""
    with open(path, 'w', encoding='utf-8') as f:
        for hs in project.hash_set.values_list('hashstring', flat=True):
            f.write('%s\n' % hs)


def start_run(run, runner=None):
    """Launch ``run`` with hashcat in a background thread.

    Returns None on success or an error string (guard failure) to show the user.
    """
    runner = runner or hc.HashcatRunner()
    if not runner.available():
        return 'hashcat is not installed on this machine.'
    if run.attack_mode != 3:
        return 'Only mask attacks (-a 3) can be launched yet.'
    if run.mask is None:
        return 'This mask attack has no mask to run.'
    if run.project is None or not run.project.hash_set.exists():
        return 'This project has no hashes to attack.'
    if run.project.hashtype is None:
        return 'This project has no hash type set.'
    with _lock:
        if Run.objects.filter(status='running').exists():
            return 'Another attack is already running (one at a time).'

    workdir = tempfile.mkdtemp(prefix='zebra-run-%d-' % run.pk)
    hashpath = os.path.join(workdir, 'hashes.txt')
    pot = os.path.join(workdir, 'zebra.pot')
    _materialize_hashfile(run.project, hashpath)

    argv = runner.build_run_args(
        3, run.project.hashtype.hashcat_module, hashfile=hashpath,
        params={'mask': run.mask.pattern, 'custom_charsets': run.mask.custom_charsets or {}},
        extra=['--status', '--status-json', '--status-timer', str(POLL_SECONDS),
               '--potfile-path', pot, '--restore-disable',
               '--session', 'zebra-%d' % run.pk])

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
    run.started_at = timezone.now()
    run.ended_at = None
    run.pid = proc.pid
    run.save(update_fields=['status', 'progress', 'started_at', 'ended_at', 'pid'])
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
            live = {k: v for k, v in summary.items() if k in ('progress', 'speed_hs')}
            if live:
                hc.ingest_status(run, live)  # progress/speed only; status from exit code

        code = proc.wait()
        run.status = _final_status(code)
        run.ended_at = timezone.now()
        run.pid = None
        if run.status == 'exhausted':
            run.progress = 1.0
        run.save(update_fields=['status', 'ended_at', 'pid', 'progress'])

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
