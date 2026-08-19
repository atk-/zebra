"""Seed / refresh HashType rows from the bundled hashcat module list.

Idempotent: rows are matched by hashcat_module, so re-running only updates
names that changed and inserts new modules. Use after updating
zebra/data/hashtypes.tsv when hashcat adds modules.
"""
from django.core.management.base import BaseCommand

from ...data import load_hashtypes
from ...models import HashType


class Command(BaseCommand):
    help = "Seed HashType records from the bundled hashcat module list."

    def add_arguments(self, parser):
        parser.add_argument('--file', help='Override the bundled hashtypes.tsv path.')

    def handle(self, *args, **options):
        created = updated = 0
        for module, name in load_hashtypes(options.get('file')):
            obj, was_created = HashType.objects.update_or_create(
                hashcat_module=module, defaults={'name': name})
            created += was_created
            updated += not was_created
        self.stdout.write(self.style.SUCCESS(
            'Seeded hashtypes: %d created, %d updated (%d total).'
            % (created, updated, HashType.objects.count())))
