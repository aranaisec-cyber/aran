# 2. Installation

## Prerequisites

- **Python 3.10 or newer.** Check yours with:

  ```bash
  python --version
  ```

  If that prints something below 3.10, or the `python` command isn't
  found at all, install a current Python from
  [python.org](https://www.python.org/downloads/) before continuing.

- **pip**, which ships with modern Python installs. Check with:

  ```bash
  pip --version
  ```

- **git**, to clone the repository (see below).

You do **not** need Node.js, Docker, or any MCP server pre-installed —
those only matter once you're wrapping a specific server, which is
covered in [4. Wiring Aran into Your IDE](04-ide-integration.md).

## Why "from source" and not `pip install aran`

Aran is not yet published to PyPI. The package name is reserved and the
project is designed to work exactly the same way once it is published
(`pip install aran`, or transparently via `uvx`), but until that step
happens, install from a clone of the repository instead. Everything else
in this guide — the `aran` command, IDE configs, the one-click badges —
works identically either way; only this one installation step is
temporary.

## Step-by-step install

```bash
git clone https://github.com/aranaisec-cyber/aran.git
cd aran
pip install -e .
```

What each line does:

1. `git clone` downloads the project source to a folder named `aran`.
2. `cd aran` moves your terminal into that folder.
3. `pip install -e .` installs the package **in editable mode** — `pip`
   reads `pyproject.toml`, installs the one dependency (`pyyaml`), and
   registers an `aran` command that points at the source files in this
   folder rather than copying them elsewhere. This means if you `git
   pull` later to get an update, you don't need to reinstall.

If you plan to run the test suite or contribute changes, install the
development extras instead, which pull in `pytest`:

```bash
pip install -e ".[dev]"
```

## Verifying the install

Run Aran with no arguments:

```bash
python -m aran.cli
```

Expected output (to stderr) and exit code 2:

```
usage: aran -- <command to launch the real MCP server> [args...]
```

Exit code 2 here is *correct* — you didn't give it a server to wrap, so it
told you the correct usage and stopped. Seeing this message means the
package installed correctly and the CLI entry point works.

This guide uses `python -m aran.cli` in every example specifically because
it works regardless of your system's `PATH` configuration — see the next
section for why that matters. Once you've confirmed `python -m aran.cli`
works, try the shorter form:

```bash
aran
```

If that prints the same usage message, both forms work interchangeably
from now on, and `aran` (the shorter form) is what you'll reference in IDE
configs in [4. Wiring Aran into Your IDE](04-ide-integration.md).

## If `aran` isn't found on your PATH

This is the single most common install hiccup, and it isn't specific to
Aran — it happens with any Python package that installs a command-line
script, especially with `pip install --user` on Windows.

**What's happening:** `pip` installed the `aran` executable into a
directory (something like
`C:\Users\<you>\AppData\Roaming\Python\Python3xx\Scripts` on Windows, or
`~/.local/bin` on Linux/macOS) that your shell doesn't currently search
when you type a bare command name. The package itself installed fine —
only the shortcut to it is missing.

**How to tell:** if `pip install` printed a warning like
`WARNING: The script aran.exe is installed in '...' which is not on
PATH`, this is exactly what's happening.

**Two ways to fix it:**

1. **Just use `python -m aran.cli` instead of `aran`.** This always works
   regardless of `PATH`, because you're asking Python to run a module by
   name rather than asking your shell to find an executable. It's more
   typing, but it needs no system changes. This is what every command in
   this guide uses.

2. **Add the script directory to your `PATH`,** so the short `aran` form
   works too (useful since IDE configs reference the short form). The
   exact directory was printed in the `pip install` warning above. On
   Windows, in PowerShell (persists across terminal sessions):

   ```powershell
   [Environment]::SetEnvironmentVariable(
     "Path",
     $env:Path + ";C:\Users\<you>\AppData\Roaming\Python\Python3xx\Scripts",
     "User"
   )
   ```

   Replace the path with the exact one from your warning, close and
   reopen your terminal, then confirm with `aran` (no arguments) —
   expect the same usage message as above.

   On Linux/macOS, add this to your `~/.bashrc` or `~/.zshrc`:

   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

   then `source ~/.bashrc` (or open a new terminal).

Either fix is fine — an IDE config that uses the short `aran` command
needs option 2; anything that lets you specify a full Python invocation
can use option 1 instead.

## Next

Continue to [3. Quickstart](03-quickstart.md) to send Aran your first
message and see it work, or jump to
[4. Wiring Aran into Your IDE](04-ide-integration.md) if you want to go
straight to a real IDE setup.
