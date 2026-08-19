"""Seed HashType rows from the bundled hashcat module list (data/hashtypes.tsv).

Self-contained (parses the bundled file directly) and idempotent: rows are keyed
on hashcat_module via update_or_create, so applying on a DB that already has some
hashtypes just fills in the rest. Reverse removes the seeded modules.
"""
from pathlib import Path

from django.db import migrations

TSV = Path(__file__).resolve().parent.parent / 'data' / 'hashtypes.tsv'


def _rows():
    rows = []
    with open(TSV, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or '\t' not in line:
                continue
            mod, name = line.split('\t', 1)
            rows.append((int(mod), name.strip()))
    return rows


def seed(apps, schema_editor):
    HashType = apps.get_model('zebra', 'HashType')
    for module, name in _rows():
        HashType.objects.update_or_create(
            hashcat_module=module, defaults={'name': name})


def unseed(apps, schema_editor):
    HashType = apps.get_model('zebra', 'HashType')
    modules = [m for m, _ in _rows()]
    HashType.objects.filter(hashcat_module__in=modules).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('zebra', '0005_alter_run_options_project_universe_run_attack_mode_and_more'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
