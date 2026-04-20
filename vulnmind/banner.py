"""
banner.py — ASCII banner printed at the top of the CLI.

Kept in its own module so it can be suppressed (JSON mode, tests) and so
tweaking the art does not churn cli.py. The banner combines the VulnMind
wordmark with the Sombra-1 author signature, rendered once per run.
"""

from __future__ import annotations

from vulnmind import __version__

_WORDMARK = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███╗   ███╗██╗███╗   ██╗██████╗
██║   ██║██║   ██║██║     ████╗  ██║████╗ ████║██║████╗  ██║██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║██╔████╔██║██║██╔██╗ ██║██║  ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║╚██╔╝██║██║██║╚██╗██║██║  ██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
"""

_SIGNATURE = r"""
                   _           ___  ___  __  __ ___ ___    _      _
                  | |__ _  _  / __|/ _ \|  \/  | _ ) _ \  /_\ ___/ |
                  | '_ \ || | \__ \ (_) | |\/| | _ \   / / _ \___| |
                  |_.__/\_, | |___/\___/|_|  |_|___/_|_\/_/ \_\  |_|
                        |__/
"""


def render(use_color: bool = True) -> str:
    """
    Return the banner as a printable string.

    When use_color is True, Rich markup is added so the caller can hand the
    result straight to a Rich Console. When False, a plain-text version is
    returned (for piped output or environments that don't render ANSI).
    """
    tagline = (
        f"v{__version__}  ·  Security scan analyzer  "
        f"·  github.com/Sombra-1/vulnmind"
    )
    if use_color:
        return (
            f"[bold cyan]{_WORDMARK}[/bold cyan]"
            f"[bold magenta]{_SIGNATURE}[/bold magenta]"
            f"  [dim]{tagline}[/dim]\n"
        )
    return f"{_WORDMARK}{_SIGNATURE}  {tagline}\n"
