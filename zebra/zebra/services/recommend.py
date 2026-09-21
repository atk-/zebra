"""Mask recommender (prototype).

Given a *time budget* and a measured hash rate, suggest a hashcat mask whose
candidate keyspace fits that budget (``keyspace ~= rate * seconds``) and that is
**maximally informative** -- preferably testing keyspace that no recorded mask
has covered yet (zero overlap).

Design
------
* A mask's keyspace is the product of its per-position class sizes, so it depends
  only on the *multiset* of character classes, not their order. We therefore
  enumerate class multisets per length (cheap: combinations-with-replacement),
  keep the ones whose keyspace lands nearest the target, and only then spend the
  (more expensive) exact-overlap computation on that short list.
* Each chosen multiset is laid out in a canonical order that mirrors a typical
  human password -- uppercase, lowercase, digits, symbols (``?u?l?l?d?d?s``) --
  which is both a sensible default shape and keeps the suggestion deterministic.
* Overlap with already-run masks is computed *exactly* by the coverage engine
  (``marginal_keyspace``), so "zero overlap" is a real guarantee, not a heuristic.

Pure module (no Django); the DB glue lives in ``coverage_helpers``.
"""

import math
from itertools import combinations_with_replacement

from . import coverage as cov

# Position order used to render a class multiset as a concrete mask: the shape of
# a typical human password (Capital, lowercase run, digits, trailing symbols).
_CANONICAL_ORDER = {'u': 0, 'l': 1, 'd': 2, 's': 3, 'a': 4, 'h': 5, 'H': 6}


def canonical_pattern(symbols):
    """Render a multiset of class symbols as a canonically ordered mask string."""
    ordered = sorted(symbols, key=lambda s: (_CANONICAL_ORDER.get(s, 99), s))
    return ''.join('?' + s for s in ordered)


def recommend(target, existing, token_sizes, max_len=16, max_eval=300, top_n=5,
              max_per_keyspace=2):
    """Rank candidate masks for a keyspace ``target`` against ``existing`` masks.

    ``target``           : desired candidate count (rate * seconds), positive int.
    ``existing``         : parsed masks already covered (list of lists of frozensets).
    ``token_sizes``      : usable classes as ``{symbol: size}`` (e.g. ``{'l':26,...}``).
    ``max_len``          : longest mask (number of positions) to consider.
    ``max_eval``         : how many nearest-by-keyspace candidates to score exactly.
    ``top_n``            : how many ranked suggestions to return.
    ``max_per_keyspace`` : cap on suggestions sharing one keyspace value, so the
                           list spans a range of shapes instead of returning many
                           same-size variants (upper/lower splits are equal size).

    Returns a list of dicts sorted best-first, each with: pattern, length,
    keyspace, marginal (new keyspace added), overlap, and log_dist (distance to
    target in natural log; 0 == exact match).
    """
    if target <= 0 or not token_sizes:
        return []
    syms = sorted(token_sizes)
    log_target = math.log(target)

    # 1. Enumerate class multisets per length; keep those nearest the target
    #    keyspace (ranking on |ln(keyspace) - ln(target)| so a 2x-too-big and a
    #    2x-too-small candidate are judged equally close).
    candidates = []
    for length in range(1, max_len + 1):
        for combo in combinations_with_replacement(syms, length):
            keyspace = 1
            for s in combo:
                keyspace *= token_sizes[s]
            log_dist = abs(math.log(keyspace) - log_target)
            candidates.append((log_dist, keyspace, combo))
    candidates.sort(key=lambda c: c[0])
    candidates = candidates[:max_eval]

    # 2. Score the short list with exact overlap against the existing masks.
    results = []
    for log_dist, keyspace, combo in candidates:
        pattern = canonical_pattern(combo)
        positions = cov.parse_mask(pattern)
        marginal = cov.marginal_keyspace(positions, existing)
        results.append({
            'pattern': pattern,
            'length': len(combo),
            'keyspace': keyspace,
            'marginal': marginal,
            'overlap': keyspace - marginal,
            'log_dist': log_dist,
        })

    # 3. Rank: fully-new masks first, then closeness to the budget, then the ones
    #    that add the most previously-untested keyspace.
    results.sort(key=lambda r: (r['overlap'] > 0, r['log_dist'], -r['marginal']))

    # 4. Diversify: keep the list from filling with equal-keyspace variants (e.g.
    #    ?u?l?l vs ?l?u?l), so the user sees a spread of shapes and sizes.
    chosen, seen = [], {}
    for r in results:
        n = seen.get(r['keyspace'], 0)
        if n >= max_per_keyspace:
            continue
        seen[r['keyspace']] = n + 1
        chosen.append(r)
        if len(chosen) >= top_n:
            break
    return chosen
