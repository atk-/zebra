"""Auto-pilot: fill an empty queue with a fresh suggested attack.

When the queue master switch is in 'auto' (see launcher) and the queue empties,
``next_auto_run`` picks an eligible project and records a new, non-redundant mask
attack sized to the configured time budget (Settings.auto_task_seconds), using the
same recommender the "Suggest mask" popup uses. DB-aware glue, like
``coverage_helpers`` / ``run_helpers``.

The recommender already excludes masks that are covered/planned/queued, so each
auto task explores new keyspace; a project whose useful masks are exhausted simply
yields nothing and auto-pilot moves to the next eligible project.
"""

from django.db.models import Max

from .models import Project, Mask, Run, Settings
from . import coverage_helpers as ch
from .services import hashcat as hc
from .services import similarity as sim


def _eligible_projects():
    """Projects auto-pilot can attack: a hash type, a benchmark, and hashes.

    Ordered by most-recent run activity, so the actively-worked campaign is fed
    first (newest first; never-run projects last)."""
    qs = (Project.objects
          .filter(hashtype__isnull=False, benchmark_hs__isnull=False)
          .annotate(last_run=Max('runs__created_at'))
          .order_by('-last_run', '-pk'))
    return [p for p in qs if p.has_hashes()]


def build_auto_run(project, seconds=None):
    """Record (as a planned Run) the top suggested attack for ``project``, or None.

    Sizes the mask to keyspace ~= benchmark_hs * seconds (Settings default when not
    given). Mirrors the mask-record path in views.mask_new: cache keyspace, generate
    the command (optimized kernels, like the form default), set the dedup signature.
    """
    if seconds is None:
        seconds = Settings.load().auto_task_seconds or 3600
    if not project.benchmark_hs:
        return None
    target = int(project.benchmark_hs) * int(seconds)
    recs = ch.project_recommendations(project, target, top_n=1)
    if not recs:
        return None
    r = recs[0]
    pattern = r['pattern']
    inc = bool(r.get('incremental'))
    inc_min = r.get('increment_min') if inc else None
    inc_max = r.get('increment_max') if inc else None

    mask, _ = Mask.objects.get_or_create(
        project=project, pattern=pattern, custom_charsets={},
        increment_min=inc_min, increment_max=inc_max)
    ch.compute_and_cache_keyspace(mask)
    mask.save()

    command = hc.configured_runner().plan_run(
        3, project.hashtype.hashcat_module, hashfile='%s.hashes' % project.name,
        params={'mask': pattern, 'custom_charsets': {},
                'increment_min': inc_min, 'increment_max': inc_max},
        optimized=True)
    sig_spec = {'attack_mode': 3, 'mask': pattern}
    if inc_min is not None:
        sig_spec['increment'] = [inc_min, inc_max]

    run = Run.objects.create(
        mask=mask, project=project, attack_mode=3, optimized=True,
        status='planned', command=command, signature=sim.signature(sig_spec),
        comment='auto-pilot')
    if not project.is_file_backed:
        run.hashes.set(project.hash_set.all())
    return run


def next_auto_run():
    """A planned auto-pilot Run for the best eligible project, or None if none fit."""
    for project in _eligible_projects():
        run = build_auto_run(project)
        if run is not None:
            return run
    return None
