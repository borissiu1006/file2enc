# ui/banner.py — Pixel block-art banner and version header

import os
from src.ui.colors import c, CYAN, GREEN, BOLD, DIM, YELLOW, WHITE, ORANGE, RED


def print_banner():
    # Use .strip('\n').split('\n') to get each individual row
    file_lines = [
        "███████╗██╗██╗     ███████╗",
        "██╔════╝██║██║     ██╔════╝",
        "█████╗  ██║██║     █████╗  ",
        "██╔══╝  ██║██║     ██╔══╝  ",
        "██║     ██║███████╗███████╗",
        "╚═╝     ╚═╝╚══════╝╚══════╝"
    ]
    
    to_lines = [
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

    print('\n')


    for i in range(len(file_lines)):
        row = (
            c(file_lines[i], ORANGE, BOLD) + 
            c(to_lines[i], DIM, BOLD) + 
            c(enc_lines[i], GREEN, BOLD)
        )
        print(row)

    print(c(f"\n  v1.1.0  \n", CYAN, BOLD))

def clear():
    os.system("cls" if os.name == "nt" else "clear")


