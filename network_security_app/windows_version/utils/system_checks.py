import os
import ctypes
import subprocess

def check_admin():
    """Vérifie si l'utilisateur a les privilèges administratifs."""
    try:
        if os.name == "nt":  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        elif os.name == "posix":  # Linux/Mac
            return os.geteuid() == 0
        else:
            print("Système d'exploitation non pris en charge pour la vérification des privilèges administratifs.")
            return False
    except Exception as e:
        print(f"Erreur lors de la vérification des privilèges administrateur : {e}")
        return False

def route_exists(ip):
    """Vérifie si une route existe déjà pour une adresse IP."""
    try:
        if os.name == "nt":  # Windows
            result = subprocess.run(["route", "print", ip], capture_output=True, text=True)
            return ip in result.stdout
        elif os.name == "posix":  # Linux/Mac
            result = subprocess.run(["ip", "route", "show", ip], capture_output=True, text=True)
            return ip in result.stdout
        else:
            print("Système d'exploitation non pris en charge pour la vérification des routes.")
            return False
    except Exception as e:
        print(f"Erreur lors de la vérification de la route pour {ip} : {e}")
        return False
