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
from itertools import chain, product

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
# ?b = any byte (0x00-0xFF); ?c = its perfect complement to ?a, i.e. every byte
# NOT in ?a (the 161 non-printable / high bytes: 0x00-0x1F, 0x7F-0xFF). ?c is a
# zebra extension -- hashcat has no native ?c, so runs express it via a custom
# charset file (see services.hashcat and b_complement.hcchr).
BUILTIN_CHARSETS['b'] = ''.join(chr(i) for i in range(256))
BUILTIN_CHARSETS['c'] = ''.join(c for c in BUILTIN_CHARSETS['b']
                                if c not in set(BUILTIN_CHARSETS['a']))


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


def expand_charset(text, wildcard_map=None):
    """Expand a hashcat-style charset spec into the set of characters it covers.

    Accepts literals and ?-tokens (``?l ?u ?d ?s ?a ?b ?h ?H`` plus project
    wildcards), e.g. ``?l?u?d?s`` -> the 94 alphanumeric+special characters, or
    ``abc012`` -> ``{a,b,c,0,1,2}``. Raises MaskParseError on an unknown token.
    Used for the project universe (the coverage-% denominator).
    """
    return _expand_charset_def(text or '', {}, wildcard_map or {})


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


# --- Disjoint-cell decomposition (for the search-space visualization) -------
#
# coverage_by_length answers *how much* keyspace is exhausted; the decomposition
# below answers *which* keyspace, in a form a UI can draw. Sigma^L partitions
# into a grid of cells (one character-atom per position); every mask is a union
# of whole cells, so the exhausted region is exactly a *disjoint* union of the
# covered cells (a DNF). No inclusion-exclusion is needed here -- grid cells are
# inherently disjoint, so we just enumerate each mask's cells and de-duplicate.
# Per-position marginals and the joint (alluvial / icicle) views all derive from
# that single cell list.

def _atom_sets(charsets):
    """Like ``atom_partition`` but also return each atom's character set.

    Returns ``(atoms, bitmasks)`` where ``atoms[a]`` is the frozenset of
    characters in atom ``a`` and ``bitmasks[i]`` is the bitmask (over atom ids)
    of the atoms composing ``charsets[i]``.
    """
    charsets = [frozenset(c) for c in charsets]
    universe = set().union(*charsets) if charsets else set()
    groups = {}     # signature (frozenset of charset indices) -> atom id
    order = []      # atom id -> signature
    members = []    # atom id -> set of characters
    for ch in universe:
        sig = frozenset(i for i, c in enumerate(charsets) if ch in c)
        aid = groups.get(sig)
        if aid is None:
            aid = len(order)
            groups[sig] = aid
            order.append(sig)
            members.append(set())
        members[aid].add(ch)
    atoms = [frozenset(m) for m in members]
    bitmasks = [0] * len(charsets)
    for aid, sig in enumerate(order):
        for idx in sig:
            bitmasks[idx] |= (1 << aid)
    return atoms, bitmasks


def _atoms_in(bitmask):
    """List of atom ids whose bit is set in ``bitmask``."""
    out = []
    aid = 0
    while bitmask:
        if bitmask & 1:
            out.append(aid)
        bitmask >>= 1
        aid += 1
    return out


def _cell_size(cell, weights):
    """Candidate count of a grid cell = product of its per-position atom weights."""
    size = 1
    for a in cell:
        size *= weights[a]
    return size


def coverage_decomposition(masks, universe=None, cell_cap=20000):
    """Disjoint-cell decomposition of the union of equal-length masks.

    ``masks``    : list of parsed masks (each a list of frozensets), same length.
    ``universe`` : characters in scope; total = len(universe)**L (else None).
    ``cell_cap`` : safety bound on enumerated cells; beyond it the joint view is
                   suppressed (``cells`` = None, ``truncated`` = True) but the
                   per-position ``marginals`` are still returned exactly.

    Returns None for an empty mask set, else a dict:
      length     : int
      covered    : int   (== sum of cell sizes; == union_keyspace(masks))
      total      : int | None
      atoms      : [ {"chars": sorted list, "weight": int} ]  # global vocabulary
      positions  : [ {"atoms": [atom_id, ...], "rest": int | None} ]  # per position
      cells      : [ {"atoms": [atom_id per pos], "size": int} ] | None
      marginals  : [ {atom_id: covered_mass} ]  # one dict per position
      truncated  : bool
    """
    masks = [m for m in masks if m]
    if not masks:
        return None
    L = len(masks[0])
    if any(len(m) != L for m in masks):
        raise ValueError('coverage_decomposition requires masks of equal length')

    distinct = list({s for m in masks for s in m})
    atoms, bits = _atom_sets(distinct)
    index = {s: bits[i] for i, s in enumerate(distinct)}
    weights = [len(a) for a in atoms]

    # per-mask, per-position list of the atom ids that make up that position-set
    mask_atoms = [[_atoms_in(index[s]) for s in m] for m in masks]

    covered = union_keyspace(masks)
    uni = set(universe) if universe is not None else None
    total = len(uni) ** L if uni is not None else None

    # atoms actually used (covered) at each position, across all masks
    used = [set() for _ in range(L)]
    for ma in mask_atoms:
        for p in range(L):
            used[p].update(ma[p])
    positions = []
    for p in range(L):
        rest = (len(uni) - sum(weights[a] for a in used[p])) if uni is not None else None
        positions.append({'atoms': sorted(used[p]), 'rest': rest})

    # enumerate the disjoint covered cells (product of atoms within each mask)
    cells_set = set()
    truncated = False
    for ma in mask_atoms:
        for combo in product(*ma):
            cells_set.add(combo)
        if len(cells_set) > cell_cap:
            truncated = True
            break

    if truncated:
        cells = None
        marginals = []
        for p in range(L):
            mp = {}
            for a in sorted(used[p]):
                subset = []
                for mi, m in enumerate(masks):
                    if a in mask_atoms[mi][p]:
                        mm = list(m)
                        mm[p] = atoms[a]
                        subset.append(mm)
                mp[a] = union_keyspace(subset) if subset else 0
            marginals.append(mp)
    else:
        cells = []
        marginals = [dict() for _ in range(L)]
        for c in cells_set:
            size = _cell_size(c, weights)
            cells.append({'atoms': list(c), 'size': size})
            for p, a in enumerate(c):
                marginals[p][a] = marginals[p].get(a, 0) + size

    return {
        'length': L,
        'covered': covered,
        'total': total,
        'atoms': [{'chars': sorted(a), 'weight': w}
                  for a, w in zip(atoms, weights)],
        'positions': positions,
        'cells': cells,
        'marginals': marginals,
        'truncated': truncated,
    }
