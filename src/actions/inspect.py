from pathlib import Path
from src.ui.colors import ask, ok, err, info, c, CYAN, DIM, YELLOW, GREEN
from src.crypto.vault import SALT_SIZE


def action_inspect():
    info("Inspect an encrypted .vault file")
    src = Path(ask("File path"))
    if not src.is_file():
        err(f"File not found: {src}"); return

    data = src.read_bytes()
    size = src.stat().st_size
    print(c(f"\n  File  : {src.resolve()}", CYAN))
    print(c(f"  Size  : {size} bytes", CYAN))
    if size > SALT_SIZE:
        print(c(f"  Salt  : {data[:SALT_SIZE].hex()}", CYAN))
        print(c(f"  Token : {data[SALT_SIZE:SALT_SIZE + 32].hex()}…", DIM))
        print(c(f"  Status: looks like a File2Enc file ✔", GREEN))
    else:
        print(c(f"  Status: file too small — may not be a vault file !!!", YELLOW))