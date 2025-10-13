# check_pw.py
import argparse
from analyzer import load_common_passwords, score_password

def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer — CLI")
    parser.add_argument("password", help="Mot de passe à évaluer (entourer par quotes si nécessaire)")
    parser.add_argument("--common", default="common_passwords.txt", help="Chemin vers la liste de mots de passe communs")
    args = parser.parse_args()

    common = load_common_passwords(args.common)
    res = score_password(args.password, common)

    print(f"Password length: {res['password_length']}")
    print(f"Estimated entropy: {res['entropy_bits']} bits")
    print(f"Pool estimate: {res['pool_estimate']}")
    print(f"Score: {res['score']} / 100  -> {res['verdict']}")
    if res['issues']:
        print("\nIssues detected:")
        for i in res['issues']:
            print(" -", i)
    if res['suggestions']:
        print("\nSuggestions:")
        for s in res['suggestions']:
            print(" -", s)

if __name__ == "__main__":
    main()
