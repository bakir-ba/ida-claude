"""Wrapper around the `claude` CLI binary. Uses the user's existing Claude
login (the same account used by Claude Code in VSCode), so no API key needed.

The CLI must be installed and logged in (`claude /login`) on the same machine.
"""
import os
import shutil
import subprocess


# On Windows, shelling out to a .cmd wrapper flashes a console window unless
# we explicitly suppress it. CREATE_NO_WINDOW hides it entirely.
_NO_WINDOW_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


class CliError(RuntimeError):
    pass


class ClaudeCliClient:
    def __init__(self):
        self._path = None

    @property
    def cli_path(self):
        if self._path is None:
            self._path = (
                shutil.which("claude")
                or shutil.which("claude.cmd")
                or shutil.which("claude.exe")
            )
        return self._path

    def available(self):
        return self.cli_path is not None

    def send(self, model, history, timeout=300):
        if not self.available():
            raise CliError(
                "`claude` CLI not found on PATH. Install Claude Code and run "
                "`claude /login` once, then restart IDA."
            )

        # Flatten the last several turns into a single prompt. Tool-use blocks
        # are skipped; only plain text survives (CLI mode is text-only).
        turns = history[-8:]
        parts = []
        for m in turns:
            content = m.get("content")
            if not isinstance(content, str):
                continue
            tag = "User" if m.get("role") == "user" else "Assistant"
            parts.append("%s:\n%s\n" % (tag, content))
        prompt = "\n".join(parts).strip() or "(no input)"


        args = [
            self.cli_path, "-p",
            "--model", model,
            "--output-format", "text",
        ]
        try:
            proc = subprocess.run(
                args,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                creationflags=_NO_WINDOW_FLAGS,
            )
        except FileNotFoundError:
            raise CliError("`claude` CLI not found.")
        except subprocess.TimeoutExpired:
            raise CliError("`claude` CLI timed out after %ds" % timeout)

        if proc.returncode != 0:
            err = (proc.stderr or "").strip() or (proc.stdout or "").strip()
            raise CliError("`claude` CLI exited %d: %s" % (proc.returncode, err))
        return (proc.stdout or "").strip() or "(empty response)"
