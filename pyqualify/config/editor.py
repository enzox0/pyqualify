"""Interactive terminal-based configuration editor with nano-like keybindings."""

from __future__ import annotations

import curses
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyqualify.config.manager import ConfigManager


class ConfigEditor:
    """Interactive terminal-based configuration editor with nano-like keybindings.

    Provides a curses-based UI for editing environment variable configuration
    in key=value format. Supports navigation, line editing, and validation.
    """

    KEYBINDINGS: dict[str, str] = {
        "Ctrl+O": "Save",
        "Ctrl+X": "Exit",
        "Ctrl+K": "Delete line",
        "↑↓←→": "Navigate",
    }

    def __init__(self, config_manager: ConfigManager) -> None:
        """Initialize the config editor.

        Args:
            config_manager: The configuration manager to load/save config from.
        """
        self._config_manager = config_manager
        self._lines: list[str] = []
        self._cursor_row: int = 0
        self._cursor_col: int = 0
        self._scroll_offset: int = 0
        self._status_message: str = ""
        self._running: bool = False
        self._screen: curses.window | None = None

    def run(self) -> None:
        """Launch the interactive editor using curses wrapper."""
        curses.wrapper(self._main)

    def _main(self, stdscr: curses.window) -> None:
        """Main editor loop.

        Args:
            stdscr: The curses standard screen window.
        """
        self._screen = stdscr
        self._setup_curses()
        self._load_config()
        self._running = True

        while self._running:
            self._draw_screen()
            key = stdscr.getch()
            self._handle_input(key)

    def _setup_curses(self) -> None:
        """Configure curses settings for the editor."""
        curses.curs_set(1)  # Show cursor
        curses.use_default_colors()
        if self._screen is not None:
            self._screen.keypad(True)

    def _load_config(self) -> None:
        """Load current configuration from the env file into editor lines."""
        env_file: Path = self._config_manager.ENV_FILE
        if env_file.exists():
            content = env_file.read_text(encoding="utf-8")
            self._lines = content.splitlines()
        else:
            # Load from config file as key=value pairs
            config = self._config_manager._load_file_config()
            self._lines = [f"{k}={v}" for k, v in sorted(config.items())]

        # Ensure at least one empty line for editing
        if not self._lines:
            self._lines = [""]

    def _draw_screen(self) -> None:
        """Draw the full editor screen: title, content, status, and keybinding bar."""
        if self._screen is None:
            return

        self._screen.clear()
        max_y, max_x = self._screen.getmaxyx()

        # Reserve lines: 1 for title, 1 for status, 2 for keybinding bar
        content_height = max_y - 4

        # Draw title bar
        title = " PyQualify Config Editor "
        self._screen.attron(curses.A_REVERSE)
        self._screen.addstr(0, 0, title.center(max_x)[:max_x])
        self._screen.attroff(curses.A_REVERSE)

        # Adjust scroll offset to keep cursor visible
        if self._cursor_row < self._scroll_offset:
            self._scroll_offset = self._cursor_row
        elif self._cursor_row >= self._scroll_offset + content_height:
            self._scroll_offset = self._cursor_row - content_height + 1

        # Draw content lines
        for i in range(content_height):
            line_idx = self._scroll_offset + i
            screen_row = i + 1  # offset by title bar
            if line_idx < len(self._lines):
                line = self._lines[line_idx]
                # Truncate line to fit screen width
                display_line = line[:max_x - 1]
                try:
                    self._screen.addstr(screen_row, 0, display_line)
                except curses.error:
                    pass
            else:
                # Draw tilde for empty lines beyond content
                try:
                    self._screen.addstr(screen_row, 0, "~")
                except curses.error:
                    pass

        # Draw status message line
        status_row = max_y - 3
        if self._status_message:
            try:
                self._screen.attron(curses.A_BOLD)
                self._screen.addstr(
                    status_row, 0, self._status_message[: max_x - 1]
                )
                self._screen.attroff(curses.A_BOLD)
            except curses.error:
                pass

        # Draw keybinding bar
        self._draw_keybinding_bar()

        # Position cursor
        cursor_screen_row = self._cursor_row - self._scroll_offset + 1
        cursor_col = min(self._cursor_col, max_x - 1)
        try:
            self._screen.move(cursor_screen_row, cursor_col)
        except curses.error:
            pass

        self._screen.refresh()

    def _draw_keybinding_bar(self) -> None:
        """Draw the keybinding reference bar at the bottom of the terminal."""
        if self._screen is None:
            return

        max_y, max_x = self._screen.getmaxyx()

        # Build keybinding display strings
        bindings = [
            ("^O", "Save"),
            ("^X", "Exit"),
            ("^K", "Del Line"),
            ("↑↓←→", "Navigate"),
        ]

        bar_row_1 = max_y - 2
        bar_row_2 = max_y - 1

        # First row of bindings
        col = 0
        for i, (key, action) in enumerate(bindings[:2]):
            entry = f" {key} {action} "
            if col + len(entry) < max_x:
                try:
                    self._screen.attron(curses.A_REVERSE)
                    self._screen.addstr(bar_row_1, col, f" {key} ")
                    self._screen.attroff(curses.A_REVERSE)
                    col += len(f" {key} ")
                    self._screen.addstr(bar_row_1, col, f"{action}  ")
                    col += len(f"{action}  ")
                except curses.error:
                    pass

        # Second row of bindings
        col = 0
        for i, (key, action) in enumerate(bindings[2:]):
            if col + len(f" {key} {action}  ") < max_x:
                try:
                    self._screen.attron(curses.A_REVERSE)
                    self._screen.addstr(bar_row_2, col, f" {key} ")
                    self._screen.attroff(curses.A_REVERSE)
                    col += len(f" {key} ")
                    self._screen.addstr(bar_row_2, col, f"{action}  ")
                    col += len(f"{action}  ")
                except curses.error:
                    pass

    def _handle_input(self, key: int) -> bool:
        """Handle a single keypress input.

        Args:
            key: The curses key code.

        Returns:
            True if the editor should continue running, False to exit.
        """
        # Clear status message on any input
        self._status_message = ""

        # Ctrl+X (exit) - ASCII 24
        if key == 24:
            self._running = False
            return False

        # Ctrl+O (save) - ASCII 15
        elif key == 15:
            errors = self._save()
            if errors:
                self._status_message = f"Errors: {'; '.join(errors)}"
            else:
                self._status_message = "Configuration saved successfully."
            return True

        # Ctrl+K (delete line) - ASCII 11
        elif key == 11:
            if len(self._lines) > 1:
                del self._lines[self._cursor_row]
                if self._cursor_row >= len(self._lines):
                    self._cursor_row = len(self._lines) - 1
                self._cursor_col = min(
                    self._cursor_col, len(self._lines[self._cursor_row])
                )
            else:
                # If only one line, clear it
                self._lines[0] = ""
                self._cursor_col = 0
            return True

        # Arrow keys
        elif key == curses.KEY_UP:
            if self._cursor_row > 0:
                self._cursor_row -= 1
                self._cursor_col = min(
                    self._cursor_col, len(self._lines[self._cursor_row])
                )
            return True

        elif key == curses.KEY_DOWN:
            if self._cursor_row < len(self._lines) - 1:
                self._cursor_row += 1
                self._cursor_col = min(
                    self._cursor_col, len(self._lines[self._cursor_row])
                )
            return True

        elif key == curses.KEY_LEFT:
            if self._cursor_col > 0:
                self._cursor_col -= 1
            elif self._cursor_row > 0:
                # Wrap to end of previous line
                self._cursor_row -= 1
                self._cursor_col = len(self._lines[self._cursor_row])
            return True

        elif key == curses.KEY_RIGHT:
            current_line = self._lines[self._cursor_row]
            if self._cursor_col < len(current_line):
                self._cursor_col += 1
            elif self._cursor_row < len(self._lines) - 1:
                # Wrap to start of next line
                self._cursor_row += 1
                self._cursor_col = 0
            return True

        # Home key
        elif key == curses.KEY_HOME:
            self._cursor_col = 0
            return True

        # End key
        elif key == curses.KEY_END:
            self._cursor_col = len(self._lines[self._cursor_row])
            return True

        # Backspace
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if self._cursor_col > 0:
                line = self._lines[self._cursor_row]
                self._lines[self._cursor_row] = (
                    line[: self._cursor_col - 1] + line[self._cursor_col :]
                )
                self._cursor_col -= 1
            elif self._cursor_row > 0:
                # Merge with previous line
                prev_line = self._lines[self._cursor_row - 1]
                current_line = self._lines[self._cursor_row]
                self._cursor_col = len(prev_line)
                self._lines[self._cursor_row - 1] = prev_line + current_line
                del self._lines[self._cursor_row]
                self._cursor_row -= 1
            return True

        # Delete key
        elif key == curses.KEY_DC:
            line = self._lines[self._cursor_row]
            if self._cursor_col < len(line):
                self._lines[self._cursor_row] = (
                    line[: self._cursor_col] + line[self._cursor_col + 1 :]
                )
            elif self._cursor_row < len(self._lines) - 1:
                # Merge with next line
                next_line = self._lines[self._cursor_row + 1]
                self._lines[self._cursor_row] = line + next_line
                del self._lines[self._cursor_row + 1]
            return True

        # Enter key
        elif key in (curses.KEY_ENTER, 10, 13):
            line = self._lines[self._cursor_row]
            # Split line at cursor position
            self._lines[self._cursor_row] = line[: self._cursor_col]
            self._lines.insert(self._cursor_row + 1, line[self._cursor_col :])
            self._cursor_row += 1
            self._cursor_col = 0
            return True

        # Regular character input
        elif 32 <= key <= 126:
            line = self._lines[self._cursor_row]
            self._lines[self._cursor_row] = (
                line[: self._cursor_col] + chr(key) + line[self._cursor_col :]
            )
            self._cursor_col += 1
            return True

        return True

    def _save(self) -> list[str]:
        """Save configuration, validating entries first.

        Returns:
            A list of error messages for invalid entries. Empty list means success.
        """
        errors = self._validate_entries(self._lines)
        if errors:
            return [
                f"Line {line_num}: {reason}" for line_num, reason in errors
            ]

        # Persist valid entries to the env file
        self._persist_entries(self._lines)
        return []

    def _validate_entries(self, lines: list[str]) -> list[tuple[int, str]]:
        """Validate that each non-empty line is in KEY=VALUE format.

        Args:
            lines: The list of lines to validate.

        Returns:
            A list of (line_number, error_reason) tuples for invalid entries.
            Line numbers are 1-based.
        """
        errors: list[tuple[int, str]] = []
        for i, line in enumerate(lines, start=1):
            # Skip empty lines and comment lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if "=" not in stripped:
                errors.append((i, "Missing '=' separator"))
                continue

            key, _, _ = stripped.partition("=")
            if not key.strip():
                errors.append((i, "Empty key"))

        return errors

    def _persist_entries(self, lines: list[str]) -> None:
        """Persist valid key=value entries to the configuration store.

        Writes entries to the env file and also updates the config manager's
        file-based config store.

        Args:
            lines: The validated lines to persist.
        """
        # Ensure config directory exists
        self._config_manager._ensure_config_dir()

        # Write raw lines to the env file
        env_file: Path = self._config_manager.ENV_FILE
        content = "\n".join(lines)
        if lines and not content.endswith("\n"):
            content += "\n"
        env_file.write_text(content, encoding="utf-8")

        # Also update the config manager's TOML store with the key=value pairs
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                self._config_manager.set(key, value)
