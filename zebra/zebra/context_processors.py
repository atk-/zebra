"""Template context processors: values injected into every rendered page."""

from .services import launcher


def queue_state(request):
    """Expose the queue master-switch state to the header (base.html)."""
    return {'queue_paused': launcher.is_paused()}
