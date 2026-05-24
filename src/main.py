
'''
file2enc v1.0.0
Copyright (c) SIU K.L.
https://github.com/borissiu1006/file2enc

'''

import sys

try:
    import cryptography  # noqa: F401
except ImportError:
    print("Missing dependency. Run:  pip install cryptography")
    sys.exit(1)

from src.ui.banner import clear, print_banner
from src.ui.menu   import print_menu, prompt_choice
from src.ui.colors import c, CYAN, BOLD, pause

from src.actions.encrypt import action_encrypt
from src.actions.decrypt import action_decrypt
from src.actions.inspect import action_inspect
from src.actions.help    import action_help

ACTIONS = {
    "encrypt": action_encrypt,
    "decrypt": action_decrypt,
    "inspect": action_inspect,
    "help":    action_help,
}


def main():
    clear()
    print_banner()
    while True:
        print_menu()
        choice = prompt_choice()
        if choice == "exit":
            print(c("Exiting FILE2ENC...\n", CYAN, BOLD))
            sys.exit(0)
        elif choice in ACTIONS:
            print()
            ACTIONS[choice]()
            pause()
            clear()
            print_banner()


if __name__ == "__main__":
    main()