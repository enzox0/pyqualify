"""Tests for the HelpModal widget.

Validates Requirements: 6.5, 6.6
"""

from __future__ import annotations

import pytest

from pyqualify.tui.widgets.help_modal import HelpModal, SHORTCUT_GROUPS


class TestHelpModalStructure:
    """Tests for HelpModal content and structure."""

    def test_shortcut_groups_defined(self) -> None:
        """All expected shortcut groups are defined."""
        group_names = [name for name, _ in SHORTCUT_GROUPS]
        assert "Global" in group_names
        assert "Navigation" in group_names
        assert "Issues Panel" in group_names
        assert "Detail Panel" in group_names
        assert "Log Panel" in group_names

    def test_global_shortcuts_include_quit_and_help(self) -> None:
        """Global group includes q (Quit) and ? (Help/Close)."""
        global_group = next(
            shortcuts for name, shortcuts in SHORTCUT_GROUPS if name == "Global"
        )
        keys = [key for key, _ in global_group]
        assert "q" in keys
        assert "?" in keys

    def test_navigation_shortcuts_include_panel_focus(self) -> None:
        """Navigation group includes 1, 2, 3 for panel focus."""
        nav_group = next(
            shortcuts for name, shortcuts in SHORTCUT_GROUPS if name == "Navigation"
        )
        keys = [key for key, _ in nav_group]
        assert "1" in keys
        assert "2" in keys
        assert "3" in keys

    def test_issues_panel_shortcuts(self) -> None:
        """Issues Panel group includes Enter, s, Up/Down, PgUp/PgDn."""
        issues_group = next(
            shortcuts
            for name, shortcuts in SHORTCUT_GROUPS
            if name == "Issues Panel"
        )
        keys = [key for key, _ in issues_group]
        assert "Enter" in keys
        assert "s" in keys
        assert "Up/Down" in keys
        assert "PgUp/PgDn" in keys

    def test_detail_panel_shortcuts(self) -> None:
        """Detail Panel group includes Escape."""
        detail_group = next(
            shortcuts
            for name, shortcuts in SHORTCUT_GROUPS
            if name == "Detail Panel"
        )
        keys = [key for key, _ in detail_group]
        assert "Escape" in keys

    def test_log_panel_shortcuts(self) -> None:
        """Log Panel group includes Up/Down for scrolling."""
        log_group = next(
            shortcuts for name, shortcuts in SHORTCUT_GROUPS if name == "Log Panel"
        )
        keys = [key for key, _ in log_group]
        assert "Up/Down" in keys

    def test_help_modal_is_modal_screen(self) -> None:
        """HelpModal inherits from ModalScreen."""
        from textual.screen import ModalScreen

        assert issubclass(HelpModal, ModalScreen)

    def test_help_modal_has_dismiss_bindings(self) -> None:
        """HelpModal has bindings for escape and question_mark to dismiss."""
        binding_keys = [b.key for b in HelpModal.BINDINGS]
        assert "escape" in binding_keys
        assert "question_mark" in binding_keys
