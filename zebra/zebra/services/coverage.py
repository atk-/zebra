"""Exact mask-coverage engine for zebra.

The valuable core of the tool: given the masks already run against a hashlist,
compute *exactly* how much of the candidate space is covered, how much is left,
and whether a new mask is redundant -- before you launch it.

Why "exact" is tractable
-------------------------
* Candidate sets of different lengths are disjoint (a 6-char string is never an
  8-char string), so masks are partitioned by length and each length is solved
  independently.
* Within a length L a mask is an L-tuple of character-sets (S_1, ..., S_L); its
  candidate set is the axis-aligned box S_1 x ... x S_L over the character
  universe.
* Atom decomposition: partition the universe into *atoms* -- maximal groups of
  characters with identical membership across all sets in play. Every set is
  then exactly a union of atoms, so a position becomes a bitmask over atoms and
  the size of any set/intersection is a sum of (integer) atom weights.
* Exact union volume via inclusion-exclusion over the masks of a length, with a
  DFS that prunes the moment an intersection becomes empty. Real mask sets
  overlap sparsely, so this runs far below the 2**n worst case.

Everything here is pure (no Django imports) and works on plain data, so it is
unit-testable without a database. All arithmetic uses native Python ints
(arbitrary precision) -- mask keyspaces routinely exceed 2**63.
"""

from functools import reduce
from itertools import chain

# --- Hashcat built-in charsets ---------------------------------------------
# Special set is printable-ASCII punctuation, starting with space (33 chars).
_SPECIAL = ' ' + '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
BUILTIN_CHARSETS = {
    'l': 'abcdefghijklmnopqrstuvwxyz',
    'u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'd': '0123456789',
    's': _SPECIAL,
    'h': '0123456789abcdef',
    'H': '0123456789ABCDEF',
}
BUILTIN_CHARSETS['a'] = (BUILTIN_CHARSETS['l'] + BUILTIN_CHARSETS['u']
                         + BUILTIN_CHARSETS['d'] + BUILTIN_CHARSETS['s'])
BUILTIN_CHARSETS['b'] = ''.join(chr(i) for i in range(256))


class MaskParseError(ValueError):
    pass


def _resolve_token(sym, custom_charsets, wildcard_map, _depth=0):
    """Return the set of characters a ``?<sym>`` token expands to."""
    if _depth > 8:
        raise MaskParseError('custom charset recursion too deep near ?%s' % sym)
    if sym == '?':
        return {'?'}
    if sym in BUILTIN_CHARSETS:
        return set(BUILTIN_CHARSETS[sym])
    # Project-defined wildcards (raw character strings).
    if wildcard_map and sym in wildcard_map:
        return set(wildcard_map[sym])
    # Hashcat custom charsets -1..-4, keyed as "1".."4" (may themselves contain
    # ?-tokens and literals).
    if custom_charsets and sym in custom_charsets:
        return _expand_charset_def(custom_charsets[sym], custom_charsets,
                                   wildcard_map, _depth + 1)
    raise MaskParseError('unknown mask token ?%s' % sym)


def _expand_charset_def(defn, custom_charsets, wildcard_map, _depth=0):
    """Expand a charset definition string (literals plus ?-tokens) to a set."""
    chars = set()
    i = 0
    while i < len(defn):
        c = defn[i]
        if c == '?' and i + 1 < len(defn):
            chars |= _resolve_token(defn[i + 1], custom_charsets, wildcard_map, _depth)
            i += 2
        else:
            chars.add(c)
            i += 1
    return chars


def parse_mask(pattern, custom_charsets=None, wildcard_map=None):
    """Parse a hashcat mask string into a list of per-position character sets.

    ``custom_charsets`` maps "1".."4" -> definition string (the -1..-4 flags).
    ``wildcard_map`` maps project-defined single-char symbols -> raw characters.
    Returns a list of ``frozenset``; ``mask_keyspace`` and friends consume it.
    """
    custom_charsets = custom_charsets or {}
    wildcard_map = wildcard_map or {}
    positions = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == '?':
            if i + 1 >= n:
                raise MaskParseError('dangling ? at end of mask %r' % pattern)
            positions.append(frozenset(
                _resolve_token(pattern[i + 1], custom_charsets, wildcard_map)))
            i += 2
        else:
            positions.append(frozenset({c}))  # literal character
            i += 1
    return positions


def mask_keyspace(positions):
    """Exact candidate count of a single mask = product of position sizes."""
    if not positions:
        return 0
    return reduce(lambda a, s: a * len(s), positions, 1)


# --- Atom decomposition -----------------------------------------------------

def atom_partition(charsets):
    """Partition the universe of ``charsets`` into disjoint atoms.

    Returns ``(weights, bitmasks)`` where ``weights[a]`` is the number of
    characters in atom ``a`` and ``bitmasks[i]`` is the bitmask (int, over atom
    ids) of the atoms making up ``charsets[i]``. Because every character in an
    atom shares the same membership across all input sets, each set is exactly a
    union of atoms.
    """
    charsets = [frozenset(c) for c in charsets]
    universe = set().union(*charsets) if charsets else set()
    # Signature of a char = the set of charset-indices that contain it.
    groups = {}  # signature (frozenset of indices) -> atom id
    order = []   # atom id -> signature
    for ch in universe:
        sig = frozenset(i for i, c in enumerate(charsets) if ch in c)
        if sig not in groups:
            groups[sig] = len(order)
            order.append(sig)
    weights = [0] * len(order)
    for ch in universe:
        sig = frozenset(i for i, c in enumerate(charsets) if ch in c)
        weights[groups[sig]] += 1
    bitmasks = [0] * len(charsets)
    for aid, sig in enumerate(order):
        for idx in sig:
            bitmasks[idx] |= (1 << aid)
    return weights, bitmasks


def _popweight(bits, weights):
    """Sum of atom weights present in the bitmask ``bits``."""
    w = 0
    while bits:
        lsb = bits & (-bits)
        w += weights[lsb.bit_length() - 1]
        bits ^= lsb
    return w


def union_keyspace(masks):
    """Exact size of the union of the candidate sets of ``masks``.

    ``masks`` is a list of parsed masks (each a list of frozensets). They must
    all be the same length; different-length masks are disjoint, so callers
    group by length first (``coverage_by_length`` does this).
    """
    masks = [m for m in masks if m]
    if not masks:
        return 0
    L = len(masks[0])
    if any(len(m) != L for m in masks):
        raise ValueError('union_keyspace requires masks of equal length')

    # One global atom partition over every position-set that appears.
    distinct = list({s for m in masks for s in m})
    weights, bits = atom_partition(distinct)
    index = {s: bits[i] for i, s in enumerate(distinct)}
    bmasks = [[index[s] for s in m] for m in masks]
    n = len(bmasks)

    total = 0

    def dfs(start, cur, sign):
        nonlocal total
        vol = 1
        for b in cur:
            vol *= _popweight(b, weights)  # b is never 0 here (pruned below)
        total += sign * vol
        for j in range(start, n):
            nxt = [cur[p] & bmasks[j][p] for p in range(L)]
            if any(b == 0 for b in nxt):
                continue  # empty intersection -> so are all its supersets
            dfs(j + 1, nxt, -sign)

    for i in range(n):
        dfs(i + 1, list(bmasks[i]), 1)
    return total


# --- Overlap / redundancy helpers ------------------------------------------

def marginal_keyspace(mask, existing):
    """New candidate space ``mask`` adds on top of ``existing`` (same length)."""
    same = [m for m in existing if len(m) == len(mask)]
    return union_keyspace(same + [mask]) - union_keyspace(same)


def is_subsumed(mask, existing):
    """True iff ``mask`` adds nothing -- already fully covered by ``existing``."""
    return marginal_keyspace(mask, existing) == 0


def overlap_keyspace(mask, existing):
    """How much of ``mask`` is already covered by ``existing``."""
    return mask_keyspace(mask) - marginal_keyspace(mask, existing)


# --- Coverage summary -------------------------------------------------------

def coverage_by_length(masks, universe=None):
    """Coverage grouped by password length.

    ``masks``   : list of parsed masks (list of frozensets).
    ``universe``: characters in scope; per-length total = len(universe)**L.
                  If None, total falls back to the union of the charsets used
                  at each position across all masks of that length.
    Returns ``{length: {"covered": int, "total": int|None, "masks": int}}``.
    """
    by_len = {}
    for m in masks:
        by_len.setdefault(len(m), []).append(m)

    out = {}
    for L, group in sorted(by_len.items()):
        covered = union_keyspace(group)
        if universe is not None:
            total = len(set(universe)) ** L
        else:
            # Fallback scope: at each position, the union of charsets used there.
            per_pos = [set().union(*(m[p] for m in group)) for p in range(L)]
            total = reduce(lambda a, s: a * len(s), per_pos, 1)
        out[L] = {'covered': covered, 'total': total, 'masks': len(group)}
    return out
