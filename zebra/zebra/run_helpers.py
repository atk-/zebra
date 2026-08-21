"""DB-aware glue between the pure similarity engine and the Django run models.

Mirrors coverage_helpers.py (which glues the coverage engine to the mask models):
this side handles non-mask runs (straight/combinator/hybrid) and near-duplicate
detection.
"""

from .models import Run, Wordlist, RuleSet
from .services import similarity as sim


def run_spec(run):
    """Build a normalized similarity spec dict from a Run instance.

    Combinator order is restored from ``params['order']`` (a list of wordlist ids),
    since the M2M itself is unordered.
    """
    p = run.params or {}
    wls = list(run.wordlists.all())
    if run.attack_mode == 1 and p.get('order'):
        by_id = {w.id: w for w in wls}
        ordered = [by_id[i] for i in p['order'] if i in by_id]
        ordered += [w for w in wls if w.id not in set(p['order'])]
        wls = ordered
    return {
        'attack_mode': run.attack_mode,
        'wordlists': [w.name for w in wls],
        'rules': [r.name for r in run.rules.all()],
        'left_rule': p.get('left_rule', ''),
        'right_rule': p.get('right_rule', ''),
        'mask': p.get('mask', ''),
        'custom_charsets': p.get('custom_charsets', {}),
    }


def evaluate_run(project, candidate_spec, exclude_run_id=None, threshold=0.5):
    """Similar existing (non-mask) runs in a project.

    Returns ``[(run, {exact, score, reasons}), ...]`` ranked by the similarity
    engine (exact duplicates first).
    """
    qs = Run.objects.filter(project=project).exclude(attack_mode=3)
    if exclude_run_id:
        qs = qs.exclude(pk=exclude_run_id)
    existing = [(run, run_spec(run))
                for run in qs.prefetch_related('wordlists', 'rules')]
    return sim.find_similar(candidate_spec, existing, threshold=threshold)


def _resolve(model, names):
    """get_or_create ``model`` rows keyed on the normalized basename.

    De-duplicates within the input; the raw string is kept as ``path`` when it
    looks like a path. Returns instances in input order.
    """
    out, seen = [], set()
    for raw in names:
        raw = (raw or '').strip()
        if not raw:
            continue
        base = sim.normalize_ref(raw)
        if not base or base in seen:
            continue
        seen.add(base)
        looks_like_path = ('/' in raw) or ('\\' in raw)
        obj, _ = model.objects.get_or_create(
            name=base, defaults={'path': raw if looks_like_path else ''})
        out.append(obj)
    return out


def resolve_wordlists(names):
    return _resolve(Wordlist, names)


def resolve_rules(names):
    return _resolve(RuleSet, names)
