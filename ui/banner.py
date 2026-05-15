# ui/banner.py — Pixel block-art banner and version header

import os
from ui.colors import c, CYAN, GREEN, BOLD, DIM, YELLOW, WHITE, ORANGE, RED


def print_banner():
    # Use .strip('\n').split('\n') to get each individual row
    seq_lines = [
        "███████╗██╗██╗     ███████╗",
        "██╔════╝██║██║     ██╔════╝",
        "█████╗  ██║██║     █████╗  ",
        "██╔══╝  ██║██║     ██╔══╝  ",
        "██║     ██║███████╗███████╗",
        "╚═╝     ╚═╝╚══════╝╚══════╝"
    ]
    
    two_lines = [
        "██████╗ ",
        "╚════██╗",
        " █████╔╝",
        "██╔═══╝ ",
        "███████╗",
        "╚══════╝"
    ]
    
    enc_lines = [
        "███████╗███╗   ██╗ ██████╗",
        "██╔════╝████╗  ██║██╔════╝",
        "█████╗  ██╔██╗ ██║██║     ",
        "██╔══╝  ██║╚██╗██║██║     ",
        "███████╗██║ ╚████║╚██████╗",
        "╚══════╝╚═╝  ╚═══╝ ╚═════╝"
    ]

    for i in range(len(seq_lines)):
        row = (
            c(seq_lines[i], ORANGE, BOLD) + 
            c(two_lines[i], DIM, BOLD) + 
            c(enc_lines[i], GREEN, BOLD)
        )
        print(row)

    print(c(f"\n  v1.1.0  \n", CYAN, BOLD))

def clear():
    os.system("cls" if os.name == "nt" else "clear")


