# ================================================
# Password Analyzer - analyzer.py
# Développé par : cntctchm
# ================================================

import math

# Charger les mots de passe communs depuis un fichier texte
def load_common_passwords(file_path="common_passwords.txt"):
    common_set = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                pwd = line.strip()
                if pwd:
                    common_set.add(pwd)
    except FileNotFoundError:
        print(f"[!] Fichier {file_path} introuvable. Liste de mots communs vide.")
    return common_set

# Calcul de l'entropie approximative
def entropy(password):
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32  # caractères spéciaux approximatifs
    if pool == 0:
        return 0
    return round(len(password) * math.log2(pool), 2)

# Scorer un mot de passe
def score_password(password, common_set):
    issues = []
    suggestions = []

    length = len(password)
    ent = entropy(password)

    if length < 6:
        issues.append("Trop court")
        suggestions.append("Utiliser au moins 8 caractères")
    if password in common_set:
        issues.append("Mot de passe très commun")
        suggestions.append("Choisir un mot de passe unique")
    if not any(c.isupper() for c in password):
        suggestions.append("Ajouter une majuscule")
    if not any(c.isdigit() for c in password):
        suggestions.append("Ajouter un chiffre")
    if not any(not c.isalnum() for c in password):
        suggestions.append("Ajouter un symbole spécial")

    # Verdict basé sur entropie et longueur
    if length < 6 or ent < 28:
        verdict = "Very Weak"
    elif length < 8 or ent < 36:
        verdict = "Weak"
    elif length < 12 or ent < 60:
        verdict = "Moderate"
    else:
        verdict = "Strong"

    return {
        "password_length": length,
        "entropy_bits": ent,
        "verdict": verdict,
        "issues": issues,
        "suggestions": suggestions
    }
