"""DB-aware glue between the pure coverage engine and the Django models."""

from decimal import Decimal

from .models import Wildcard, Mask
from .services import coverage as cov


def project_wildcard_map():
    """Map of project-defined wildcard symbols -> their raw character strings."""
    return {w.symbol: w.characters for w in Wildcard.objects.all()}


def mask_positions(mask, wildcard_map=None):
    """Parse a Mask model instance into engine positions (list of frozensets)."""
    if wildcard_map is None:
        wildcard_map = project_wildcard_map()
    return cov.parse_mask(mask.pattern,
                          custom_charsets=mask.custom_charsets or {},
                          wildcard_map=wildcard_map)


def compute_and_cache_keyspace(mask):
    """Set mask.length / mask.keyspace from the engine (does not save)."""
    positions = mask_positions(mask)
    mask.length = len(positions)
    mask.keyspace = Decimal(cov.mask_keyspace(positions))
    return mask


def project_coverage(project):
    """Coverage-by-length summary for every mask stored in a project.

    Returns a sorted list of row dicts ready for templating, each with:
    length, masks, covered, total, remaining, percent.
    """
    wmap = project_wildcard_map()
    parsed = []
    for m in project.masks.all():
        try:
            parsed.append(mask_positions(m, wmap))
        except cov.MaskParseError:
            continue  # skip malformed masks rather than break the dashboard
    universe = project.universe or None
    summary = cov.coverage_by_length(parsed, universe=universe)
    rows = []
    for length, data in sorted(summary.items()):
        covered, total = data['covered'], data['total']
        percent = (100.0 * covered / total) if total else 0.0
        rows.append({
            'length': length,
            'masks': data['masks'],
            'covered': covered,
            'total': total,
            'remaining': (total - covered) if total else None,
            'percent': percent,
        })
    return rows


def evaluate_candidate(project, pattern, custom_charsets=None):
    """Assess a candidate mask against a project's existing masks.

    Returns a dict: keyspace, length, overlap, marginal, subsumed, error.
    """
    wmap = project_wildcard_map()
    try:
        positions = cov.parse_mask(pattern, custom_charsets=custom_charsets or {},
                                   wildcard_map=wmap)
    except cov.MaskParseError as exc:
        return {'error': str(exc)}
    existing = []
    for m in project.masks.all():
        try:
            existing.append(mask_positions(m, wmap))
        except cov.MaskParseError:
            continue
    keyspace = cov.mask_keyspace(positions)
    marginal = cov.marginal_keyspace(positions, existing)
    return {
        'error': None,
        'length': len(positions),
        'keyspace': keyspace,
        'marginal': marginal,
        'overlap': keyspace - marginal,
        'subsumed': marginal == 0 and keyspace > 0,
    }
