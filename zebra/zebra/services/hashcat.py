"""Thin, optional, read-only wrapper around the ``hashcat`` binary.

Hybrid design: zebra *reads* from hashcat (benchmarks, keyspace cross-check,
result import) but does not launch or manage long cracking jobs. Everything here
degrades gracefully when hashcat is not installed, so the rest of the app keeps
working with purely manual data entry.

The ``HashcatRunner`` class is the seam a future *active* launcher plugs into:
``plan()`` / ``import_*`` exist today; ``launch()`` / ``poll()`` are stubs.
Parsing helpers (``parse_potfile`` / ``parse_status_json``) are pure and DB-free;
the ``ingest_*`` functions apply parsed results to the Django models.
"""

import json
import shutil
import subprocess

DEFAULT_BINARY = 'hashcat'


class HashcatError(RuntimeError):
    pass


class HashcatRunner:
    def __init__(self, binary=DEFAULT_BINARY, potfile_path=None):
        self.binary = binary
        self.potfile_path = potfile_path

    # -- availability --------------------------------------------------------
    def available(self):
        return shutil.which(self.binary) is not None

    def _run(self, args, timeout=None):
        if not self.available():
            raise HashcatError('hashcat binary %r not found on PATH' % self.binary)
        try:
            proc = subprocess.run([self.binary] + args, capture_output=True,
                                  text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HashcatError('failed to run hashcat: %s' % exc)
        return proc

    # -- read-only queries ---------------------------------------------------
    def keyspace(self, mask, custom_charsets=None):
        """Return hashcat's ``--keyspace`` for a mask (attack mode 3).

        NOTE: for -a 3 this is hashcat's host-side chunking number, NOT the
        candidate count. Use services.coverage.mask_keyspace for coverage math;
        this is only for hashcat-terms runtime estimates / cross-checks.
        """
        args = ['--keyspace', '-a', '3']
        args += _charset_flags(custom_charsets)
        args.append(mask)
        proc = self._run(args, timeout=60)
        if proc.returncode != 0:
            raise HashcatError('hashcat --keyspace failed: %s'
                               % (proc.stderr.strip() or proc.stdout.strip()))
        for line in reversed(proc.stdout.splitlines()):
            line = line.strip()
            if line.isdigit():
                return int(line)
        raise HashcatError('could not parse --keyspace output: %r' % proc.stdout)

    def benchmark(self, module, timeout=600):
        """Return (speed_hs, raw_output) for a hash module via ``hashcat -b``.

        Speed is a best-effort parse of --machine-readable output (summing the
        largest numeric field per device line); the raw output is returned too.
        """
        proc = self._run(['-b', '-m', str(module), '--machine-readable',
                           '--quiet'], timeout=timeout)
        if proc.returncode != 0:
            raise HashcatError('hashcat -b failed: %s'
                               % (proc.stderr.strip() or proc.stdout.strip()))
        return parse_benchmark(proc.stdout), proc.stdout

    # -- command planning ----------------------------------------------------
    def plan(self, module, mask, hashfile='HASHFILE', custom_charsets=None,
             device=None, extra=None):
        """Build (but do not run) the hashcat command string for a mask attack."""
        parts = [self.binary, '-m', str(module), '-a', '3']
        parts += _charset_flags(custom_charsets)
        if device:
            parts += ['-d', str(device)]
        if self.potfile_path:
            parts += ['--potfile-path', self.potfile_path]
        if extra:
            parts += list(extra)
        parts += [hashfile, mask]
        return ' '.join(parts)

    def build_run_args(self, attack_mode, module, hashfile='HASHFILE', wordlists=None,
                       rules=None, params=None, device=None, extra=None):
        """Build the hashcat **argv list** for any supported attack mode.

        ``wordlists``/``rules`` are lists of path-or-name strings. Returned as a
        list so callers can Popen it directly (no shell -> no injection);
        ``plan_run`` joins it for display. ``extra`` are launcher flags appended
        before the positional hashfile/attack args.
        """
        params = params or {}
        wordlists = [str(w) for w in (wordlists or [])]
        rules = [str(r) for r in (rules or [])]
        parts = [self.binary, '-m', str(module), '-a', str(attack_mode)]
        if device:
            parts += ['-d', str(device)]
        if self.potfile_path:
            parts += ['--potfile-path', self.potfile_path]
        if extra:
            parts += list(extra)

        if attack_mode == 3:
            flags, mask = _mask_charset_args(params)
            parts += flags + [hashfile, mask]
        elif attack_mode == 0:
            for r in rules:
                parts += ['-r', r]
            parts += [hashfile] + wordlists
        elif attack_mode == 1:
            if params.get('left_rule'):
                parts += ['-j', params['left_rule']]
            if params.get('right_rule'):
                parts += ['-k', params['right_rule']]
            parts += [hashfile,
                      wordlists[0] if len(wordlists) > 0 else 'LEFT',
                      wordlists[1] if len(wordlists) > 1 else 'RIGHT']
        elif attack_mode == 6:  # wordlist + mask
            flags, mask = _mask_charset_args(params)
            parts += flags + [hashfile, wordlists[0] if wordlists else 'WORDLIST', mask]
        elif attack_mode == 7:  # mask + wordlist
            flags, mask = _mask_charset_args(params)
            parts += flags + [hashfile, mask, wordlists[0] if wordlists else 'WORDLIST']
        else:
            parts += [hashfile]
        return [str(p) for p in parts]

    def plan_run(self, attack_mode, module, hashfile='HASHFILE', wordlists=None,
                 rules=None, params=None, device=None):
        """Build (but do not run) a hashcat command string for display."""
        return ' '.join(self.build_run_args(
            attack_mode, module, hashfile=hashfile, wordlists=wordlists,
            rules=rules, params=params, device=device))

    # -- future active launcher (seam) --------------------------------------
    def launch(self, *a, **k):  # pragma: no cover - future work
        raise NotImplementedError('active launching is a future phase')

    def poll(self, *a, **k):  # pragma: no cover - future work
        raise NotImplementedError('active launching is a future phase')


def _charset_flags(custom_charsets):
    """Turn {"1": "?l?d", ...} into ['-1', '?l?d', ...]."""
    flags = []
    for key in sorted((custom_charsets or {}).keys()):
        flags += ['-' + str(key), str(custom_charsets[key])]
    return flags


def c_complement_path():
    """Absolute path to the ?c-complement charset file (b_complement.hcchr).

    Read from the ``ZEBRA_C_COMPLEMENT_PATH`` setting when Django is configured,
    else fall back to the copy shipped at the repo root."""
    try:
        from django.conf import settings
        path = getattr(settings, 'ZEBRA_C_COMPLEMENT_PATH', None)
        if path:
            return str(path)
    except Exception:
        pass
    import os
    return os.path.abspath(os.path.join(
        os.path.dirname(__file__), '..', '..', '..', 'b_complement.hcchr'))


def substitute_c(mask, custom_charsets, c_path):
    """Rewrite ``?c`` tokens to a custom -1..-4 slot bound to the complement file.

    hashcat has no native ``?c``; we bind a free custom-charset slot to ``c_path``
    (hashcat's ``-N`` accepts a filename) and rewrite each ``?c`` token to ``?N``.
    A no-op when the mask has no ``?c``. Tokens are scanned so a literal ``??`` is
    never mistaken for a ``?c`` token. Returns ``(mask, custom_charsets)``; if all
    four custom slots are taken, ``?c`` is left as-is (best effort).
    """
    custom = dict(custom_charsets or {})

    def has_c_token(m):
        i, n = 0, len(m)
        while i < n:
            if m[i] == '?' and i + 1 < n:
                if m[i + 1] == 'c':
                    return True
                i += 2  # skip the whole ?-token (so a literal ?? never matches)
            else:
                i += 1
        return False

    if not has_c_token(mask):
        return mask, custom
    slot = next((s for s in ('1', '2', '3', '4') if s not in custom), None)
    if slot is None:
        return mask, custom
    custom[slot] = str(c_path)
    out, i, n = [], 0, len(mask)
    while i < n:
        if mask[i] == '?' and i + 1 < n:
            out.append('?' + (slot if mask[i + 1] == 'c' else mask[i + 1]))
            i += 2
        else:
            out.append(mask[i])
            i += 1
    return ''.join(out), custom


def _mask_charset_args(params):
    """(custom-charset flags, mask string) for a mask, with ``?c`` translated."""
    mask, custom = substitute_c(params.get('mask', ''),
                                params.get('custom_charsets'), c_complement_path())
    return _charset_flags(custom), mask


# --- pure parsers -----------------------------------------------------------

def parse_potfile(text):
    """Parse potfile lines ``<hash>:<plaintext>`` -> list of (hash, plaintext).

    Only the first colon is treated as the separator (plaintext may contain
    colons); blank lines are skipped.
    """
    pairs = []
    for line in text.splitlines():
        line = line.rstrip('\n')
        if not line:
            continue
        h, sep, plain = line.partition(':')
        if sep:
            pairs.append((h, plain))
    return pairs


def parse_status_json(text):
    """Parse hashcat ``--status-json`` output into a small summary dict.

    Returns keys: status (int), progress (float 0..1), speed_hs (int),
    recovered (int), recovered_total (int). Missing fields are omitted.
    """
    data = json.loads(text)
    out = {}
    if 'status' in data:
        out['status'] = data['status']
    prog = data.get('progress')
    if isinstance(prog, list) and len(prog) == 2 and prog[1]:
        out['progress'] = prog[0] / prog[1]
    speed = 0
    for dev in data.get('devices', []) or []:
        speed += dev.get('speed', 0)
    if speed:
        out['speed_hs'] = int(speed)
    rec = data.get('recovered_hashes')
    if isinstance(rec, list) and len(rec) == 2:
        out['recovered'], out['recovered_total'] = rec[0], rec[1]
    return out


def parse_benchmark(text):
    """Total speed (H/s) from ``hashcat -b --machine-readable`` output.

    Each device line is colon-separated, e.g. (hashcat v6)::

        1:0:4294967295:4294967295:62.19:375777106
        dev  mode  <----sentinels---->  exec_ms  speed(H/s)

    The **last** field is the per-device H/s; we sum it across device lines. The
    two ``4294967295`` (0xFFFFFFFF) fields are placeholders -- an earlier "largest
    field per line" heuristic latched onto that sentinel (2**32-1) and reported a
    bogus ~4.29 GH/s for any hash slower than that. Returns an int (0 if none).
    """
    total = 0
    for line in text.splitlines():
        fields = line.strip().split(':')
        if len(fields) < 3:
            continue  # not a benchmark device line (needs at least dev:mode:...:speed)
        try:
            total += int(float(fields[-1]))
        except ValueError:
            continue  # banner / non-numeric line
    return total


# --- Django-side ingest -----------------------------------------------------

def ingest_cracks(project, pairs, run=None):
    """Apply (hash, plaintext) pairs to a project's hashes.

    Marks matching Hash rows cracked and records Crack rows. Returns the number
    of hashes newly matched. Django models are imported lazily so the parsers
    above stay usable without a configured Django environment.
    """
    from ..models import Crack

    plaintext_by_hash = dict(pairs)
    matched = 0
    for h in project.hash_set.filter(hashstring__in=plaintext_by_hash.keys()):
        plain = plaintext_by_hash[h.hashstring]
        if not h.cracks.filter(plaintext=plain).exists():
            Crack.objects.create(hash=h, plaintext=plain, run=run)
        if not h.cracked:
            h.cracked = True
            h.save(update_fields=['cracked'])
            matched += 1
    return matched


def ingest_status(run, summary):
    """Apply a parse_status_json summary dict to a Run."""
    fields = []
    if 'progress' in summary:
        run.progress = summary['progress']
        fields.append('progress')
    if 'speed_hs' in summary:
        run.speed_hs = summary['speed_hs']
        fields.append('speed_hs')
    # hashcat status: 5 = exhausted, 6 = cracked, 7 = aborted (best-effort map)
    status_map = {5: 'exhausted', 6: 'cracked', 7: 'aborted'}
    if summary.get('status') in status_map:
        run.status = status_map[summary['status']]
        fields.append('status')
    if fields:
        run.save(update_fields=fields)
    return fields
