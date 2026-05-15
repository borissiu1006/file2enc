# ui/menu.py — Arrow-key navigable menu with a framed box

import sys
from ui.colors import c, BOLD, GREEN, DIM, WHITE, ORANGE, visible_len

MENU_ITEMS = [
    ("Encrypt a file",            "encrypt"),
    ("Decrypt a file",            "decrypt"),
    ("Inspect an encrypted file", "inspect"),
    ("Help",                      "help"),
    ("Exit",                      "exit"),
]

# ── Box drawing ────────────────────────────────────────────────────────────────
W = 52

def _box_top():    return c("╭" + "─" * W + "╮", GREEN)
def _box_bot():    return c("╰" + "─" * W + "╯", GREEN)
def _box_row(txt): return c("│", GREEN) + txt + c("│", GREEN)

def _render_menu(selected: int):
    lines = []
    lines.append(_box_top())

    header_text = c(" ! ", GREEN, BOLD) + c("Start", WHITE, BOLD)
    pad = W - visible_len(header_text) - 1
    lines.append(_box_row(f" {header_text}" + " " * pad))
    lines.append(_box_row(" " * W))

    for i, (label, _) in enumerate(MENU_ITEMS):
        if i == selected:
            item_str = f"  {c('●', ORANGE)} {c(f'{i+1}. {label}', WHITE, BOLD)}"
        else:
            item_str = f"    {c(f'{i+1}. {label}', DIM)}"

        item_pad = W - visible_len(item_str)
        lines.append(_box_row(item_str + " " * item_pad))

    lines.append(_box_bot())
    return lines


# ── Cross-platform key reader ──────────────────────────────────────────────────

def _read_key() -> str:
    if sys.platform == "win32":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):  # special key prefix on Windows
            ch2 = msvcrt.getwch()
            return f"\x00{ch2}"
        return ch
    else:
        import tty, termios
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                ch3 = sys.stdin.read(1)
                return f"\x1b{ch2}{ch3}"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _is_up(key):   return key in ("\x00H", "\x1b[A")
def _is_down(key): return key in ("\x00P", "\x1b[B")


# ── Interactive prompt ─────────────────────────────────────────────────────────

def prompt_choice() -> str:
    selected = 0
    n = len(MENU_ITEMS)

    lines = _render_menu(selected)
    print("\n".join(lines))
    total_lines = len(lines)

    while True:
        key = _read_key()

        if _is_up(key):
            selected = (selected - 1) % n
        elif _is_down(key):
            selected = (selected + 1) % n
        elif key in ("\r", "\n"):
            print()
            return MENU_ITEMS[selected][1]
        elif key == "\x03":         # Ctrl-C
            return "exit"
        elif key.isdigit() and 1 <= int(key) <= n:
            selected = int(key) - 1

        sys.stdout.write(f"\033[{total_lines}A\r")
        print("\n".join(_render_menu(selected)))


def print_menu():
    pass