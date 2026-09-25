"""Recompute every Mask's cached keyspace exactly from the coverage engine.

Run this once after migrating the keyspace/benchmark columns off DecimalField (which
SQLite rounded past ~15 digits) so previously-rounded cached keyspaces become exact
again. Idempotent and safe to re-run; it needs no hashcat (the engine is pure Python
``int``). Benchmark/speed values cannot be recomputed here -- re-measure those with
``hashcat -b`` if precision matters.
"""
from django.core.management.base import BaseCommand

from ...coverage_helpers import compute_and_cache_keyspace
from ...models import Mask


class Command(BaseCommand):
    help = "Recompute all Mask.keyspace values exactly from the engine."

    def handle(self, *args, **options):
        changed = skipped = 0
        for mask in Mask.objects.all():
            before = mask.keyspace
            try:
                compute_and_cache_keyspace(mask)
            except Exception as exc:  # a malformed stored pattern must not abort the run
                skipped += 1
                self.stderr.write('skipped mask %s (%r): %s' % (mask.pk, mask.pattern, exc))
                continue
            if mask.keyspace != before:
                mask.save(update_fields=['length', 'keyspace'])
                changed += 1
        self.stdout.write(self.style.SUCCESS(
            'Recomputed keyspaces: %d updated, %d skipped (%d total).'
            % (changed, skipped, Mask.objects.count())))
