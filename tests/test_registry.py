"""Tests for the extensions plugin registry."""

import logging
import sys
import types
from unittest.mock import MagicMock, Mock, patch

import pytest

from aegisvault.extensions.registry import load_plugins, load_provider_plugins


def _make_entry_point(name: str, load_return=None, load_side_effect=None):
    """Create a fake entry point with a configurable load() method."""
    ep = Mock()
    ep.name = name
    if load_side_effect is not None:
        ep.load.side_effect = load_side_effect
    else:
        ep.load.return_value = load_return
    return ep


class _FakeEPGroup:
    """Mimics the object returned by importlib.metadata.entry_points()."""

    def __init__(self, eps):
        self._eps = eps

    def select(self, *, group):
        return [ep for ep in self._eps if ep.group == group]


# ---------------------------------------------------------------------------
# load_plugins
# ---------------------------------------------------------------------------


class TestLoadPlugins:
    def test_calls_register_for_each_entry_point(self):
        """Every loaded plugin should be invoked with the register callback."""
        plugin_a = Mock()
        plugin_b = Mock()

        ep_a = _make_entry_point("plugin_a", load_return=plugin_a)
        ep_b = _make_entry_point("plugin_b", load_return=plugin_b)
        ep_a.group = "my.group"
        ep_b.group = "my.group"

        fake_eps = _FakeEPGroup([ep_a, ep_b])
        register = Mock()

        with patch("aegisvault.extensions.registry.entry_points", return_value=fake_eps):
            load_plugins("my.group", register)

        plugin_a.assert_called_once_with(register)
        plugin_b.assert_called_once_with(register)

    def test_failing_entry_point_logs_warning_and_continues(self, caplog):
        """A plugin that raises during load must not prevent subsequent plugins."""
        good_plugin = Mock()
        bad_ep = _make_entry_point("bad", load_side_effect=RuntimeError("boom"))
        good_ep = _make_entry_point("good", load_return=good_plugin)
        bad_ep.group = "grp"
        good_ep.group = "grp"

        fake_eps = _FakeEPGroup([bad_ep, good_ep])
        register = Mock()

        with (
            patch("aegisvault.extensions.registry.entry_points", return_value=fake_eps),
            caplog.at_level(logging.WARNING, logger="aegisvault.extensions.registry"),
        ):
            load_plugins("grp", register)

        # The good plugin still ran
        good_plugin.assert_called_once_with(register)
        # A warning was emitted for the bad one
        assert any("Failed to load plugin bad" in rec.message for rec in caplog.records)

    def test_failing_plugin_call_logs_warning(self, caplog):
        """A plugin whose callable body raises is also handled gracefully."""
        exploding_plugin = Mock(side_effect=ValueError("nope"))

        ep = _make_entry_point("exploder", load_return=exploding_plugin)
        ep.group = "grp"

        fake_eps = _FakeEPGroup([ep])
        register = Mock()

        with (
            patch("aegisvault.extensions.registry.entry_points", return_value=fake_eps),
            caplog.at_level(logging.WARNING, logger="aegisvault.extensions.registry"),
        ):
            load_plugins("grp", register)

        assert any("Failed to load plugin exploder" in rec.message for rec in caplog.records)

    def test_no_matching_entry_points_does_nothing(self):
        """When no entry points match the group, nothing should happen."""
        ep = _make_entry_point("unrelated")
        ep.group = "other.group"

        fake_eps = _FakeEPGroup([ep])
        register = Mock()

        with patch("aegisvault.extensions.registry.entry_points", return_value=fake_eps):
            load_plugins("my.group", register)

        register.assert_not_called()

    def test_empty_entry_points_does_nothing(self):
        """Completely empty entry points should be a no-op."""
        fake_eps = _FakeEPGroup([])
        register = Mock()

        with patch("aegisvault.extensions.registry.entry_points", return_value=fake_eps):
            load_plugins("my.group", register)

        register.assert_not_called()


# ---------------------------------------------------------------------------
# load_provider_plugins
# ---------------------------------------------------------------------------


class TestLoadProviderPlugins:
    def test_calls_register_provider(self):
        """load_provider_plugins should call load_plugins with the providers group."""
        fake_provider_mod = types.ModuleType("aegisvault.model.provider")
        fake_provider_mod.register_provider = Mock()

        with (
            patch.dict(sys.modules, {"aegisvault.model.provider": fake_provider_mod}),
            patch("aegisvault.extensions.registry.load_plugins") as mock_load,
        ):
            load_provider_plugins()

        mock_load.assert_called_once_with(
            "aegisvault.providers", fake_provider_mod.register_provider
        )

    def test_custom_provider_registration_via_plugin(self):
        """End-to-end: a plugin that registers a custom provider factory."""
        register = Mock()
        custom_factory = Mock()

        def my_plugin(register_cb):
            register_cb("custom-llm", custom_factory)

        ep = _make_entry_point("custom_llm_ep", load_return=my_plugin)
        ep.group = "aegisvault.providers"

        fake_eps = _FakeEPGroup([ep])

        with patch("aegisvault.extensions.registry.entry_points", return_value=fake_eps):
            load_plugins("aegisvault.providers", register)

        register.assert_called_once_with("custom-llm", custom_factory)
