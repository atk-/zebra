"""Template context processors: values injected into every rendered page."""

from .services import launcher


def queue_state(request):
    """Expose the queue master-switch mode to the header (base.html)."""
    return {'queue_mode': launcher.queue_mode()}
