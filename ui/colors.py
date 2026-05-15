# ui/colors.py — ANSI colour constants and helper
import re

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"
ORANGE = "\033[38;5;208m"
BLACK  = "\033[30m"


def c(text: str, *codes: str) -> str:
    """Wrap text with one or more ANSI codes, then reset."""
    return "".join(codes) + text + RESET


def ok(msg: str):   print(c(f"\n  ✔  {msg}", GREEN))
def err(msg: str):  print(c(f"\n  ✘  {msg}", RED))
def info(msg: str): print(c(f"\n  [i]  {msg}", CYAN))


def ask(prompt: str, secret: bool = False) -> str:
    import getpass
    fn = getpass.getpass if secret else input
    return fn(c(f"  {prompt}: ", YELLOW)).strip()


def pause():
    input(c("\n  Press Enter to return to the menu…", DIM))


def visible_len(text):
    """Returns the length of the string without ANSI escape codes."""
    # This magic string finds all ANSI codes and removes them
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return len(ansi_escape.sub('', text))