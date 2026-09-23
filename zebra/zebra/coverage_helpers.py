"""DB-aware glue between the pure coverage engine and the Django models."""

from decimal import Decimal

from .models import Wildcard, Mask
from .services import coverage as cov
from .services import recommend as rec


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


def mask_expansion(mask, wildcard_map=None):
    """The parsed masks a Mask contributes to coverage (list of lists of frozensets).

    A plain mask contributes just itself; an incremental (``--increment``) mask
    contributes one prefix per swept length. This is the single place mask/increment
    is turned into engine masks, so coverage, overlap and the recommender all agree."""
    positions = mask_positions(mask, wildcard_map)
    if mask.is_incremental:
        return cov.mask_prefixes(positions, mask.increment_min, mask.increment_max)
    return [positions]


def compute_and_cache_keyspace(mask):
    """Set mask.length / mask.keyspace from the engine (does not save).

    For an incremental mask, keyspace is the sum over its swept length-prefixes."""
    positions = mask_positions(mask)
    mask.length = len(positions)
    if mask.is_incremental:
        mask.keyspace = Decimal(cov.incremental_keyspace(
            positions, mask.increment_min, mask.increment_max))
    else:
        mask.keyspace = Decimal(cov.mask_keyspace(positions))
    return mask


def expand_universe(text):
    """Expand a project's universe spec (hashcat shorthands or literals) to the set
    of characters used as the coverage-% denominator, or None if unset/invalid."""
    if not text:
        return None
    try:
        return cov.expand_charset(text) or None
    except cov.MaskParseError:
        return None


def covered_masks(project):
    """Masks that count as covered: those with at least one exhausted run.

    Single source of truth for "actually-searched keyspace" -- a mask only counts
    once a run against it has been recorded as exhausted (keyspace fully searched).
    """
    return Mask.objects.filter(project=project, runs__status='exhausted').distinct()


def project_coverage(project):
    """Coverage-by-length summary for a project's exhausted-run masks.

    Returns a sorted list of row dicts ready for templating, each with:
    length, masks, covered, total, remaining, percent.
    """
    wmap = project_wildcard_map()
    parsed = []
    for m in covered_masks(project):
        try:
            parsed.extend(mask_expansion(m, wmap))  # incremental masks -> prefixes
        except cov.MaskParseError:
            continue  # skip malformed masks rather than break the dashboard
    summary = cov.coverage_by_length(parsed, universe=expand_universe(project.universe))
    rows = []
    for length, data in sorted(summary.items()):
        covered, total = data['covered'], data['total']
        percent = (100.0 * covered / total) if total else 0.0
        rows.append({
            'length': length,
            'masks': data['masks'],
            'covered': covered,
            'total': total,
            # Clamp for display: ?b/?c can search beyond the project universe, so
            # covered may exceed total. Cap remaining at 0 and coverage at 100%
            # rather than showing negatives / >100% (the underlying mismatch is a
            # separate, deferred issue).
            'remaining': max(total - covered, 0) if total else None,
            'percent': min(percent, 100.0),
        })
    return rows


def project_covered_expansion(project, wmap=None):
    """Flattened parsed masks already covered (incremental masks -> prefixes)."""
    wmap = wmap or project_wildcard_map()
    existing = []
    for m in covered_masks(project):
        try:
            existing.extend(mask_expansion(m, wmap))
        except cov.MaskParseError:
            continue
    return existing


def evaluate_candidate(project, pattern, custom_charsets=None,
                       increment_min=None, increment_max=None):
    """Assess a candidate mask against a project's existing masks.

    ``increment_min`` set marks a ``--increment`` candidate: its keyspace/overlap are
    summed over the swept length-prefixes. For an incremental candidate, the
    effective ``increment_min`` is auto-raised past any *leading* lengths whose
    mask-prefix is already fully covered by exhausted runs (a sweep is a contiguous
    range, so only a leading run can be skipped) -- e.g. after an exhaustive ``?a``
    sweep of lengths 1-6, a new ``?d`` sweep starts at length 7. Returns a dict:
    keyspace, length, overlap, marginal, overlap_pct, subsumed, incremental,
    increment_min (effective), increment_min_requested, increment_skipped,
    redundant_increment, increment_max, error.
    """
    wmap = project_wildcard_map()
    try:
        positions = cov.parse_mask(pattern, custom_charsets=custom_charsets or {},
                                   wildcard_map=wmap)
    except cov.MaskParseError as exc:
        return {'error': str(exc)}
    incremental = increment_min is not None
    existing = project_covered_expansion(project, wmap)
    requested_min = increment_min
    increment_skipped = 0
    redundant = False
    if incremental:
        n = len(positions)
        lo0 = max(1, increment_min)
        hi = min(n, increment_max if increment_max is not None else n)
        # Advance past leading length-prefixes that add nothing new (fully covered).
        lo = lo0
        while lo <= hi and cov.mask_keyspace(positions[:lo]) > 0 \
                and cov.is_subsumed(positions[:lo], existing):
            lo += 1
        increment_skipped = lo - lo0
        increment_min, increment_max = lo, hi
        redundant = lo > hi  # every swept length was already covered
        segments = [] if redundant else cov.mask_prefixes(positions, lo, hi)
    else:
        segments = [positions]
    keyspace = sum(cov.mask_keyspace(s) for s in segments)
    marginal = sum(cov.marginal_keyspace(s, existing) for s in segments)
    overlap = keyspace - marginal
    return {
        'error': None,
        'length': len(positions),
        'keyspace': keyspace,
        'marginal': marginal,
        'overlap': overlap,
        'overlap_pct': (100.0 * overlap / keyspace) if keyspace else 0.0,
        'subsumed': (marginal == 0 and keyspace > 0) or redundant,
        'incremental': incremental,
        'increment_min': increment_min if incremental else None,
        'increment_min_requested': requested_min if incremental else None,
        'increment_skipped': increment_skipped,
        'redundant_increment': redundant,
        'increment_max': increment_max if incremental else None,
    }


# --- Mask recommender (glue) ------------------------------------------------

# Character classes the recommender builds masks from. The four core classes
# (l/u/d/s) are pairwise disjoint, so two core-only masks collide only when they
# are the identical class-tuple. ``a`` (all 95 printable ASCII = l+u+d+s) is also
# offered: it reaches big keyspaces in fewer positions, at the cost of overlapping
# any core mask -- but overlap is computed exactly by the engine, so such masks
# are simply ranked below zero-overlap ones rather than being wrong.
_RECO_CLASSES = ['l', 'u', 'd', 's', 'a']


def project_token_sizes(universe_chars):
    """Usable ``{class symbol: size}`` for a project's universe.

    A class is offered only when it is wholly within the universe (so masks stay
    in scope -- e.g. ``?a`` is dropped unless every one of its 95 characters is in
    the universe). With no universe set, every class is offered; for an exotic
    custom universe that contains no whole class, fall back to the core four so
    the recommender still has something to work with.
    """
    sizes = {}
    for sym in _RECO_CLASSES:
        chars = set(cov.BUILTIN_CHARSETS[sym])
        if universe_chars is None or chars <= universe_chars:
            sizes[sym] = len(chars)
    if not sizes:
        sizes = {sym: len(cov.BUILTIN_CHARSETS[sym]) for sym in ('l', 'u', 'd', 's')}
    return sizes


def project_recommendations(project, target, top_n=8):
    """Ranked mask suggestions for a project given a keyspace ``target``.

    Gathers the project's already-covered masks and in-scope classes, then defers
    to the pure ``recommend`` engine. Returns its ranked list (may be empty).
    """
    existing = project_covered_expansion(project)  # incremental masks -> prefixes
    token_sizes = project_token_sizes(expand_universe(project.universe))
    return rec.recommend(int(target), existing, token_sizes, top_n=top_n)


# --- Search-space decomposition (visualization glue) ------------------------
#
# Wraps cov.coverage_decomposition with human-readable atom labels/colors and
# JSON-safe stringification of the (arbitrary-precision) keyspace integers --
# JS numbers lose precision past 2**53, so every keyspace count is sent as a
# string and only coerced to float for pixel geometry on the client.

# Disjoint core categories used both for atom colouring and subset labels.
_CORE = ['d', 'l', 'u', 's']
_NOUN = {'d': 'digits', 'l': 'lowercase', 'u': 'uppercase', 's': 'symbols',
         'x': 'chars'}


def _atom_label_class(chars, name_table):
    """(label, css_class) for an atom given its sorted character list."""
    s = frozenset(chars)
    cls = _core_class(s)
    exact = name_table.get(s)
    if exact is not None:
        return exact, cls
    if len(chars) == 1:
        c = chars[0]
        return ("'%s'" % c) if c.isprintable() else ('1 %s' % _NOUN[cls]), cls
    return '%d %s' % (len(chars), _NOUN[cls]), cls


def _core_class(s):
    """Colour class: the single core category that contains the atom, else 'x'."""
    hit = None
    for sym in _CORE:
        if s <= frozenset(cov.BUILTIN_CHARSETS[sym]):
            if hit is not None:
                return 'x'  # straddles more than one core category
            hit = sym
    return hit or 'x'


def _sample(chars, n=8):
    """A short printable sample of an atom's characters for tooltips."""
    printable = [c for c in chars if c.isprintable() and c != ' ']
    picked = (printable or chars)[:n]
    more = '…' if len(chars) > len(picked) else ''
    return ''.join(picked) + more


def _s(n):
    """Stringify an int for JSON (preserve precision); pass through None."""
    return None if n is None else str(n)


def project_length_decomposition(project, length):
    """JSON-serialisable disjoint-cell decomposition for one password length.

    Feeds the embedded search-space visualization: labelled atoms, disjoint
    covered cells, per-position marginals, and summary stats. Keyspace counts
    are strings (JS precision-safe).
    """
    wmap = project_wildcard_map()
    parsed = []
    for m in covered_masks(project):
        try:
            segments = mask_expansion(m, wmap)  # incremental masks -> prefixes
        except cov.MaskParseError:
            continue
        parsed.extend(pos for pos in segments if len(pos) == length)
    if not parsed:
        return {'length': length, 'empty': True}

    universe = expand_universe(project.universe)
    dec = cov.coverage_decomposition(parsed, universe=universe)

    # name table: exact-set -> display symbol (builtins + project wildcards)
    name_table = {}
    for sym in ('l', 'u', 'd', 's', 'a', 'h', 'H', 'b'):
        name_table[frozenset(cov.BUILTIN_CHARSETS[sym])] = '?' + sym
    for w in Wildcard.objects.all():
        name_table.setdefault(frozenset(w.characters), '?' + w.symbol)

    atoms = []
    for a in dec['atoms']:
        label, cls = _atom_label_class(a['chars'], name_table)
        atoms.append({'label': label, 'cls': cls,
                      'weight': _s(a['weight']), 'sample': _sample(a['chars'])})

    positions = [{'atoms': p['atoms'], 'rest': _s(p['rest'])}
                 for p in dec['positions']]
    cells = None
    if dec['cells'] is not None:
        cells = sorted(({'atoms': c['atoms'], 'size': _s(c['size'])}
                        for c in dec['cells']),
                       key=lambda c: int(c['size']), reverse=True)
    marginals = [{str(a): _s(v) for a, v in mp.items()} for mp in dec['marginals']]

    redundancy = sum(cov.mask_keyspace(m) for m in parsed) - dec['covered']
    total = dec['total']
    percent = (100.0 * dec['covered'] / total) if total else None
    return {
        'length': length,
        'empty': False,
        'masks': len(parsed),
        'covered': _s(dec['covered']),
        'total': _s(total),
        'percent': percent,
        'atoms': atoms,
        'positions': positions,
        'cells': cells,
        'marginals': marginals,
        'truncated': dec['truncated'],
        'redundancy': _s(redundancy),
        'cell_count': (len(cells) if cells is not None else None),
        'fingerprint': [len(p['atoms']) for p in positions],
    }
