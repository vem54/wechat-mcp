import signal

import pytest

from wechat_bridge.archive import daemon


@pytest.mark.parametrize("ending", [signal.SIGTERM, signal.SIGINT, "exception"])
def test_background_sync_shares_owner_lock_and_restores_handlers(monkeypatch, ending):
    config = object()
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    validated = []
    captured = []
    monkeypatch.setattr(daemon, "ArchiveWatcher", lambda cfg, **kwargs: validated.append((cfg, kwargs)))

    def exclusive(cfg, stop, **kwargs):
        assert cfg is config
        assert kwargs == {"retry_seconds": 2.0, "debounce_seconds": .5, "reconcile_seconds": 30}
        assert not stop.is_set()
        captured.append(stop)
        if ending == "exception":
            raise RuntimeError("test_failure")
        signal.getsignal(ending)(ending, None)
        assert stop.is_set()

    monkeypatch.setattr(daemon, "run_exclusive", exclusive)
    if ending == "exception":
        with pytest.raises(RuntimeError, match="test_failure"):
            daemon.run_watcher(config, debounce_seconds=.5, reconcile_seconds=30)
    else:
        daemon.run_watcher(config, debounce_seconds=.5, reconcile_seconds=30)
    assert validated == [(config, {"debounce_seconds": .5, "reconcile_seconds": 30})]
    assert captured[0].is_set()
    assert all(signal.getsignal(signum) == handler for signum, handler in previous.items())


def test_background_sync_validates_before_taking_over_handlers(monkeypatch):
    previous = signal.getsignal(signal.SIGTERM)

    def invalid(*_args, **_kwargs):
        raise ValueError("not_ready")

    monkeypatch.setattr(daemon, "ArchiveWatcher", invalid)
    with pytest.raises(ValueError, match="not_ready"):
        daemon.run_watcher(object())
    assert signal.getsignal(signal.SIGTERM) == previous
