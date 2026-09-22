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
* We diversify by **length**: the best mask for each length is chosen, and the
  result is filled with the best-fitting distinct lengths first, so the top
  suggestions span the whole band of lengths that can approximate the budget
  (a short, character-rich mask vs a longer, simpler one, same runtime).
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


def _rank_key(r):
    """Sort key: fully-new masks first, then closest to the budget, then adds most."""
    return (r['overlap'] > 0, r['log_dist'], -r['marginal'])


def recommend(target, existing, token_sizes, max_len=16, per_len=12, top_n=8):
    """Suggest masks fitting a keyspace ``target``, spanning as many lengths as it can.

    ``target``      : desired candidate count (rate * seconds), a positive int.
    ``existing``    : parsed masks already covered (list of lists of frozensets).
    ``token_sizes`` : usable classes as ``{symbol: size}`` (e.g. ``{'l':26,...}``).
    ``max_len``     : longest mask (number of positions) to consider.
    ``per_len``     : how many nearest-by-keyspace candidates to score per length.
    ``top_n``       : how many suggestions to return.

    A length ``L`` can approximate the target when ``min_size**L <= target <=
    max_size**L``; those lengths form a contiguous band ``[M, N]`` in which some
    class mix hits the budget almost exactly. To let the user trade a short,
    character-rich mask against a longer, simpler one, we return the best mask for
    each length in that band (evenly sampled if there are more lengths than
    ``top_n``), so the suggestions span the applicable lengths.

    Masks that are 100% overlapping (fully redundant -- every candidate already
    exhausted) are dropped, since suggesting them is worthless; a length whose
    fitting masks are all fully covered simply drops out, trading a little length
    coverage for only-useful suggestions.

    Returns a list of dicts (pattern, length, keyspace, marginal, overlap,
    log_dist), ordered by length for a readable short-to-long progression.
    """
    if target <= 0 or not token_sizes:
        return []
    syms = sorted(token_sizes)
    log_target = math.log(target)

    # 1. Per length, score the `per_len` multisets whose keyspace is nearest the
    #    target (|ln(keyspace) - ln(target)|, so 2x-over and 2x-under tie), with
    #    exact overlap against the existing masks. Every length gets a shot, so
    #    the whole applicable band is represented rather than just the closest.
    scored_by_len = {}
    for length in range(1, max_len + 1):
        cands = []
        for combo in combinations_with_replacement(syms, length):
            keyspace = 1
            for s in combo:
                keyspace *= token_sizes[s]
            cands.append((abs(math.log(keyspace) - log_target), keyspace, combo))
        cands.sort(key=lambda c: c[0])
        results = []
        for log_dist, keyspace, combo in cands[:per_len]:
            pattern = canonical_pattern(combo)
            marginal = cov.marginal_keyspace(cov.parse_mask(pattern), existing)
            if marginal == 0:
                continue  # 100% overlap -- fully redundant, worth nothing to suggest
            results.append({
                'pattern': pattern, 'length': length, 'keyspace': keyspace,
                'marginal': marginal, 'overlap': keyspace - marginal,
                'log_dist': log_dist,
            })
        results.sort(key=_rank_key)
        if results:
            scored_by_len[length] = results

    # 2. The lengths that can *fit* the budget form a contiguous band [M, N]:
    #    min_size**L <= target <= max_size**L. Cover one best mask per length in
    #    that band, so the suggestions span every applicable length rather than
    #    clustering on the single closest one.
    smin, smax = min(token_sizes.values()), max(token_sizes.values())
    M = max(1, math.ceil(log_target / math.log(smax)))
    N = min(max_len, math.floor(log_target / math.log(smin)))
    band = [scored_by_len[L][0] for L in range(M, N + 1) if L in scored_by_len]

    if band:
        # More applicable lengths than slots -> sample evenly across [M, N] so the
        # spread still reaches both ends of the band.
        chosen = _even_sample(band, top_n) if len(band) > top_n else band
    else:
        # Target unreachable at any length within max_len: fall back to the
        # closest lengths so we still return something useful.
        chosen = sorted((rs[0] for rs in scored_by_len.values()),
                        key=_rank_key)[:top_n]

    # 3. Present short-to-long so the length spread reads at a glance.
    chosen.sort(key=lambda r: (r['length'], r['log_dist']))
    return chosen


def _even_sample(items, k):
    """Pick ``k`` items evenly spread across ``items`` (both ends included)."""
    n = len(items)
    if k >= n:
        return items
    if k == 1:
        return [items[0]]
    idx = sorted({round(i * (n - 1) / (k - 1)) for i in range(k)})
    return [items[i] for i in idx]
