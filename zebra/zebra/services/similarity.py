"""Similarity engine for non-mask attacks (wordlist / combinator / hybrid).

Their keyspace can't be computed the way masks' can, so instead of exact
coverage this module detects when a run is identical or *near*-identical to one
already recorded -- the same "don't repeat work" value the mask overlap check
gives, for attacks zebra can only track, not measure.

Pure and DB-free (mirrors services.coverage), so it's unit-testable without a
database. It operates on plain **spec dicts**:

    {"attack_mode": int,
     "wordlists": [name, ...],      # order matters for combinator
     "rules": [name, ...],          # rule *files* (-r)
     "left_rule": str, "right_rule": str,   # combinator inline -j/-k
     "mask": str, "custom_charsets": {..}}  # hybrid

Wordlist/rule *file* names are normalised to basename+lowercase so
``/usr/share/wordlists/rockyou.txt`` matches ``rockyou.txt``.
"""

import os


def normalize_ref(s):
    """Basename + lowercase of a file reference (path-insensitive matching)."""
    if not s:
        return ''
    return os.path.basename(str(s).strip()).lower()


def _norm_list(xs):
    return [normalize_ref(x) for x in (xs or []) if str(x).strip()]


def _jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def signature(spec):
    """Deterministic canonical key for exact-duplicate detection."""
    m = spec.get('attack_mode')
    wl = _norm_list(spec.get('wordlists'))
    rules = ','.join(sorted(_norm_list(spec.get('rules'))))
    if m == 0:
        return '0|w=%s|r=%s' % (','.join(sorted(wl)), rules)
    if m == 1:  # order-sensitive pair + inline (non-file) rules
        left = wl[0] if len(wl) > 0 else ''
        right = wl[1] if len(wl) > 1 else ''
        return '1|l=%s|r=%s|j=%s|k=%s' % (
            left, right, (spec.get('left_rule') or '').strip(),
            (spec.get('right_rule') or '').strip())
    if m in (6, 7):
        cs = spec.get('custom_charsets') or {}
        csig = ','.join('%s=%s' % (k, cs[k]) for k in sorted(cs))
        return '%d|w=%s|m=%s|c=%s' % (
            m, wl[0] if wl else '', (spec.get('mask') or '').strip(), csig)
    if m == 3:
        return '3|m=%s' % (spec.get('mask') or '').strip()
    return '%s|?' % m


def similarity(a, b):
    """Compare two specs. Returns {exact, score(0..1), reasons[]} or None if the
    two are not comparable (incompatible attack modes)."""
    ma, mb = a.get('attack_mode'), b.get('attack_mode')
    if ma != mb and not ({ma, mb} <= {6, 7}):
        return None

    if ma == 0 and mb == 0:
        wa, wb = set(_norm_list(a.get('wordlists'))), set(_norm_list(b.get('wordlists')))
        ra, rb = set(_norm_list(a.get('rules'))), set(_norm_list(b.get('rules')))
        exact = wa == wb and ra == rb
        reasons = []
        if exact:
            reasons.append('identical wordlist(s) and rules')
        elif wa == wb:
            if ra <= rb or rb <= ra:
                reasons.append('same wordlist(s); one rule set is a subset of the '
                               'other (likely redundant)')
            elif ra & rb:
                reasons.append('same wordlist(s); overlapping rules')
            else:
                reasons.append('same wordlist(s); different rules')
        elif ra == rb and (wa & wb):
            reasons.append('same rules; overlapping wordlists')
        elif (wa & wb) or (ra & rb):
            reasons.append('overlapping wordlists/rules')
        return {'exact': exact, 'score': 0.5 * _jaccard(wa, wb) + 0.5 * _jaccard(ra, rb),
                'reasons': reasons}

    if ma == 1 and mb == 1:
        wa, wb = _norm_list(a.get('wordlists')), _norm_list(b.get('wordlists'))
        inline_a = ((a.get('left_rule') or '').strip(), (a.get('right_rule') or '').strip())
        inline_b = ((b.get('left_rule') or '').strip(), (b.get('right_rule') or '').strip())
        if wa == wb and inline_a == inline_b:
            return {'exact': True, 'score': 1.0,
                    'reasons': ['identical combinator pair and rules']}
        if len(wa) == 2 and wa[::-1] == wb:
            return {'exact': False, 'score': 0.8,
                    'reasons': ['combinator pair reversed (overlapping space)']}
        if wa == wb:
            return {'exact': False, 'score': 0.7,
                    'reasons': ['same combinator pair; different -j/-k rules']}
        j = _jaccard(wa, wb)
        return {'exact': False, 'score': j,
                'reasons': ['overlapping combinator wordlists'] if j else []}

    if ma in (6, 7) and mb in (6, 7):
        wa = _norm_list(a.get('wordlists')); wb = _norm_list(b.get('wordlists'))
        wa1, wb1 = (wa[0] if wa else ''), (wb[0] if wb else '')
        mask_a, mask_b = (a.get('mask') or '').strip(), (b.get('mask') or '').strip()
        cs_a, cs_b = a.get('custom_charsets') or {}, b.get('custom_charsets') or {}
        same = wa1 == wb1 and mask_a == mask_b and cs_a == cs_b
        if same and ma == mb:
            return {'exact': True, 'score': 1.0,
                    'reasons': ['identical hybrid wordlist + mask']}
        if same and ma != mb:
            return {'exact': False, 'score': 0.85,
                    'reasons': ['hybrid direction swapped (6 <-> 7, same wordlist + mask)']}
        if wa1 and wa1 == wb1:
            return {'exact': False, 'score': 0.6,
                    'reasons': ['same hybrid wordlist; different mask']}
        if mask_a and mask_a == mask_b:
            return {'exact': False, 'score': 0.6,
                    'reasons': ['same hybrid mask; different wordlist']}
        return None

    return None


def find_similar(candidate, existing, threshold=0.5):
    """Rank ``existing`` [(ref, spec), ...] by similarity to ``candidate``.

    Returns [(ref, result), ...] for exact matches or score >= threshold,
    exact-duplicates first, then by descending score.
    """
    out = []
    for ref, spec in existing:
        result = similarity(candidate, spec)
        if result is None:
            continue
        if result['exact'] or result['score'] >= threshold:
            out.append((ref, result))
    out.sort(key=lambda t: (not t[1]['exact'], -t[1]['score']))
    return out
