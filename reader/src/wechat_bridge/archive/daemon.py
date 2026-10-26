"""Signal-aware, single-owner archive sync for a local background service."""
import signal
import threading

from .watcher import ArchiveWatcher, run_exclusive


def run_watcher(config, *, debounce_seconds=1.0, reconcile_seconds=60.0):
    """Keep sync independent of an AI client; never start or control WeChat.

    The same owner lock is used by MCP fallback watchers. SIGTERM cancels any
    refresh in progress without publishing an incomplete archive generation.
    """
    ArchiveWatcher(config, debounce_seconds=debounce_seconds, reconcile_seconds=reconcile_seconds)
    stop = threading.Event()
    previous = {}

    def shutdown(_signum, _frame):
        stop.set()

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, shutdown)
        run_exclusive(config, stop, retry_seconds=2.0,
                      debounce_seconds=debounce_seconds, reconcile_seconds=reconcile_seconds)
    finally:
        stop.set()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
