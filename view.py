from art import *
from colorama import Fore, init

init()

def line50():
    return Fore.LIGHTBLUE_EX + ("─" * 50) + Fore.RESET

def novaAscii():
    ascii_art = text2art("Nova", font='doom')
    line = "─" * 50
    colored_lines = Fore.LIGHTBLUE_EX + line + Fore.RESET
    colored_ascii_art = Fore.LIGHTBLUE_EX + ascii_art + Fore.RESET
    print(colored_lines)
    print(colored_ascii_art)
    print(colored_lines)

def choices():
    colors = {
        '[': Fore.LIGHTBLUE_EX + '[' + Fore.RESET,
        ']': Fore.LIGHTBLUE_EX + ']' + Fore.RESET,
    }

    options = {
        1: f"{colors['[']}{Fore.RED}1{Fore.RESET}{colors[']']} {Fore.RED}HASH{Fore.RESET}",
        2: f"{colors['[']}{Fore.GREEN}2{Fore.RESET}{colors[']']} {Fore.GREEN}DECRYPT{Fore.RESET}",
        3: f"{colors['[']}{Fore.YELLOW}3{Fore.RESET}{colors[']']} {Fore.YELLOW}INFO{Fore.RESET}",
        4: f"{colors['[']}{Fore.CYAN}4{Fore.RESET}{colors[']']} {Fore.CYAN}EXIT{Fore.RESET}",
    }

    for key in options:
        print(options[key])

    choice = None

    try:
        choice = int(input(Fore.LIGHTBLUE_EX + "Select an option: " + Fore.RESET))
        if not choice in options:
            print(f"{Fore.CYAN}Error value: write a number between 1 and 4!{Fore.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}EXITED!{Fore.RESET}")
    except ValueError:
        print(f"{Fore.CYAN}Error value: write a number between 1 and 4!{Fore.RESET}")

    return choice if choice is not None and choice in options else None