"""Bundled reference data for zebra."""
from pathlib import Path

HASHTYPES_TSV = Path(__file__).resolve().parent / 'hashtypes.tsv'
# Charset file holding every byte of ?c (the perfect complement of ?a). hashcat has
# no native ?c token, so mask runs that use ?c bind a custom -1..-4 slot to this file.
C_COMPLEMENT_HCCHR = Path(__file__).resolve().parent / 'b_complement.hcchr'


def load_hashtypes(path=None):
    """Parse the bundled hashcat module list into (module_id, name) tuples."""
    path = Path(path) if path else HASHTYPES_TSV
    rows = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or '\t' not in line:
                continue
            mod, name = line.split('\t', 1)
            rows.append((int(mod), name.strip()))
    return rows
