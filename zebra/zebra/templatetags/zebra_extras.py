"""Dashboard number formatting filters."""

from django import template

register = template.Library()

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
