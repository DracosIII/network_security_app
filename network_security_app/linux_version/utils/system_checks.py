import os

def check_admin():
    """Vérifie si l'utilisateur a les privilèges administratifs."""
    try:
        return os.geteuid() == 0
    except Exception as e:
        print(f"Erreur lors de la vérification des privilèges administrateur : {e}")
        return False
