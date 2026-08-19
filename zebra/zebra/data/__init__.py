"""Bundled reference data for zebra."""
from pathlib import Path

HASHTYPES_TSV = Path(__file__).resolve().parent / 'hashtypes.tsv'


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
