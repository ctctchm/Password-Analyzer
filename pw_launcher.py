# ================================================
# Password Analyzer - pw_launcher.py
# Développé par : cntctchm
# ================================================

import os
from analyzer import load_common_passwords, score_password
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

console = Console()

# Charger la liste des mots de passe communs
common_set = load_common_passwords("common_passwords.txt")

# Menu principal
def main_menu():
    while True:
        console.clear()
        console.rule("[bold cyan]Password Analyzer[/bold cyan] - Développé par cntctchm")
        console.print("1. Analyser un mot de passe")
        console.print("2. Quitter")
        choice = Prompt.ask("Choisissez une option", choices=["1","2"], default="1")

        if choice == "1":
            analyze_password()
            console.print("\nAppuyez sur Entrée pour revenir au menu...")
            input()
        else:
            console.print("\nMerci d'avoir utilisé Password Analyzer !")
            break

# Couleur selon verdict
def verdict_style(verdict):
    styles = {
        "Very Weak": "bold red",
        "Weak": "orange1",
        "Moderate": "yellow",
        "Strong": "green"
    }
    return styles.get(verdict, "white")

# Fonction d'analyse d'un mot de passe
def analyze_password():
    console.print("\n[bold]Analyse d'un mot de passe[/bold]\n")
    pw = Prompt.ask("Entrez le mot de passe")
    res = score_password(pw, common_set)

    table = Table(title="Résultat de l'analyse")
    table.add_column("Critère", style="cyan", no_wrap=True)
    table.add_column("Valeur", style="magenta")

    table.add_row("Longueur", str(res["password_length"]))
    table.add_row("Entropie approx.", str(res["entropy_bits"]))
    table.add_row("Verdict", f"[{verdict_style(res['verdict'])}]{res['verdict']}[/{verdict_style(res['verdict'])}]")

    if res.get("issues"):
        table.add_row("Problèmes détectés", ", ".join(res["issues"]))
    if res.get("suggestions"):
        table.add_row("Suggestions", ", ".join(res["suggestions"]))

    console.print(table)

# Lancer le menu
if __name__ == "__main__":
    main_menu()
