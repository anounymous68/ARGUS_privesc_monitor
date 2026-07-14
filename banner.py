"""
ARGUS — Linux Privilege Escalation Monitor
Author: Mostafa Tamime

CLI banner module. Import and call print_banner() at daemon startup
(in main.py, before the asyncio loop starts).
"""

from colorama import init, Fore, Style

init(autoreset=True)

ARGUS_LOGO = r"""
   /\   /\______  _______ _    _  _____
  /  \ / / ___/ | / / ___/| |  | |/ ___/
 / /\ V / (_ /| |/ (_ /  | |  | \___ \
/_/  \_/\___/ |___/\___/  |__|_|/____/

        A  R  G  U  S
"""

# Alternative eye-themed banner (more Metasploit-skull-vibes)
ARGUS_LOGO_EYE = (
    "           _.-''''''-._\n"
    "         .'            `.\n"
    "        /   .--------.   \\\n"
    "       |   / .-''''-. \\   |\n"
    "       |  |  ()    () |  |    A R G U S\n"
    "       |   \\  `----'  /   |   the watcher that never sleeps\n"
    "        \\   `--------'   /\n"
    "         `._            _.'\n"
    "            `--......--'\n"
)


def print_banner(version: str = "0.1.0-mvp"):
    print(Fore.CYAN + Style.BRIGHT + ARGUS_LOGO)
    print(Fore.YELLOW + "        " + "-" * 46)
    print(Fore.GREEN + Style.BRIGHT +
          "        ARGUS" + Fore.WHITE +
          " — Linux Privilege Escalation Monitor")
    print(Fore.WHITE + f"        v{version}" +
          Fore.LIGHTBLACK_EX + "  |  Blue Team Daemon  |  Not linPEAS")
    print(Fore.MAGENTA + "        Author by " + Style.BRIGHT + "Mostafa Tamime")
    print(Fore.YELLOW + "        " + "-" * 46 + "\n")
    print(Fore.LIGHTBLACK_EX +
          "        \"He who watches every gate, misses no thief.\"\n")


if __name__ == "__main__":
    print_banner()
