"""Dashboard number formatting filters."""

from django import template
from django.utils.html import format_html
from django.utils.safestring import mark_safe

register = template.Library()

# hashcat builtin charset letter -> colour class (mirrors the coverage-viz atom hues).
# ?a/?b/?h/?H are broad/other -> 'x'; custom ?1-?4 (or anything else) -> 'c'.
_MASK_ATOM = {'l': 'l', 'u': 'u', 'd': 'd', 's': 's',
              'a': 'x', 'b': 'x', 'h': 'x', 'H': 'x'}


def _tokenize_mask(pattern):
    """Split a hashcat mask into (kind, char) tokens.

    ``('wild', 'd')`` for ``?d`` etc.; ``('lit', c)`` for a literal (``??`` -> a
    literal ``?``). Mirrors hashcat: ``?`` followed by a token char is a wildcard,
    a doubled ``??`` is a literal question mark, everything else is literal."""
    tokens, i, n = [], 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == '?' and i + 1 < n:
            nxt = pattern[i + 1]
            tokens.append(('lit', '?') if nxt == '?' else ('wild', nxt))
            i += 2
        else:
            tokens.append(('lit', c))
            i += 1
    return tokens


@register.filter
def mask_spec(mask):
    """Render a Mask pattern as readable, colour-coded HTML.

    Wildcards lose their ``?`` and become the bold, hue-coded charset letter
    (``?d`` -> a bold green ``d``); literals stay plain. So ``abc?d?d?d?s`` renders as
    ``abc`` then bold ``d d d s``. Incremental masks get a muted ``(incr min–max)``
    suffix. All dynamic text is escaped (format_html), so the result is safe HTML."""
    if mask is None:
        return ''
    pieces = []
    for kind, ch in _tokenize_mask(mask.pattern or ''):
        if kind == 'wild':
            pieces.append(format_html('<b class="mch mch-{}">{}</b>',
                                      _MASK_ATOM.get(ch, 'c'), ch))
        else:
            pieces.append(format_html('<span class="mlit">{}</span>', ch))
    html = mark_safe(''.join(pieces))  # pieces are already escaped by format_html
    if mask.is_incremental:
        hi = mask.increment_max if mask.increment_max is not None else mask.length
        html = format_html('{} <span class="muted">(incr {}–{})</span>',
                           html, mask.increment_min, hi)
    return html

# Superscript digits for the "n × 10^k" exponent (kept as plain Unicode so the
# value needs no HTML / mark_safe and renders anywhere a string does).
_SUPERSCRIPT = str.maketrans('0123456789-', '⁰¹²³⁴⁵⁶⁷⁸⁹⁻')


@register.filter
def bignum(value):
    """Comma-group an integer, or switch to ``n × 10ᵏ`` notation past 12 digits.

    Keyspaces routinely reach dozens of digits; grouping stays readable up to
    ~10^12, beyond which "2.18 × 10¹⁴" is clearer than a 15-digit run of commas.
    Non-numeric / None values pass through unchanged."""
    if value is None or value == '':
        return value
    try:
        i = int(value)
    except (TypeError, ValueError):
        return value
    if len(str(abs(i))) > 12:
        mantissa, exponent = '{:.2e}'.format(float(i)).split('e')
        return '%s × 10%s' % (mantissa, str(int(exponent)).translate(_SUPERSCRIPT))
    return '{:,}'.format(i)
