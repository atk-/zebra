"""Pure helpers for file-backed hash projects (no Django imports).

For very large hashlists a project references an external file on disk instead of
ingesting one ``Hash`` row per line. This module does the file-side work — line
counting, path validation, and reading recovered-hash counts from a hashcat
potfile — with no database or Django dependency, so it's unit-testable with
``SimpleTestCase`` (mirroring ``services.coverage`` / ``services.similarity``).

The DB-aware glue (which project is file-backed, where its potfile lives) lives on
the ``Project`` model, which calls into here.
"""

import os

_CHUNK = 1 << 20  # 1 MiB streamed read; never loads a multi-GB file into memory


def count_lines(path):
    """Count non-empty lines in ``path`` (each is one hash hashcat will attack).

    Streamed in chunks so a multi-gigabyte file is never read whole. Blank lines
    are skipped (hashcat ignores them, and the DB ingest path strips them too), so
    this matches the true candidate/target count. A file with no trailing newline
    still has its last line counted.
    """
    count = 0
    carry = ''  # partial trailing line spanning a chunk boundary
    with open(path, 'r', encoding='utf-8', errors='ignore', newline='') as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            chunk = carry + chunk
            lines = chunk.split('\n')
            carry = lines.pop()  # last element is the (possibly partial) final line
            for line in lines:
                if line.strip():
                    count += 1
        if carry.strip():  # final line without a trailing newline
            count += 1
    return count


def validate_path(path):
    """Validate a server-side hashfile path. Returns ``(ok, error)``.

    Requires an absolute path to an existing, readable regular file. (The tool is
    a local single-operator utility, so any readable file is allowed; an optional
    allowlist could be layered on here later.)
    """
    if not path:
        return False, 'No path given.'
    if not os.path.isabs(path):
        return False, 'Path must be absolute.'
    if not os.path.exists(path):
        return False, 'No such file: %s' % path
    if not os.path.isfile(path):
        return False, 'Not a regular file: %s' % path
    if not os.access(path, os.R_OK):
        return False, 'File is not readable: %s' % path
    return True, None


# Cache potfile line counts so a huge potfile isn't rescanned on every dashboard
# load. Keyed on (path, mtime_ns, size): any hashcat append changes mtime/size and
# invalidates the entry naturally. Process-local; fine for a single-operator app.
_potfile_cache = {}


def potfile_cracked_count(potfile_path):
    """Number of recovered hashes = number of lines in the project potfile.

    Each potfile line is one ``hash:plaintext`` crack. Returns 0 when the potfile
    doesn't exist yet (no cracks). Result is cached on (path, mtime, size).
    """
    try:
        st = os.stat(potfile_path)
    except OSError:
        return 0
    key = (potfile_path, st.st_mtime_ns, st.st_size)
    hit = _potfile_cache.get(potfile_path)
    if hit and hit[0] == key:
        return hit[1]
    count = count_lines(potfile_path)
    _potfile_cache[potfile_path] = (key, count)
    return count
