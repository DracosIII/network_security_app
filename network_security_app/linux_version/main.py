import sys
import os
import multiprocessing
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from dotenv import load_dotenv, set_key

# Ajouter dynamiquement le chemin du projet au sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.append(project_root)

from web.server import app  # Importer le serveur Flask
from ui.login_window import LoginWindow
from auth.auth_manager import AuthManager
from ui.main_window import MainWindow
from utils.system_checks import check_admin

def save_env_variable(key, value):
    """Sauvegarde une variable dans le fichier .env."""
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    set_key(env_path, key, value)

def start_web_server():
    """Démarre le serveur Flask dans un processus séparé."""
    app.run(host='0.0.0.0', port=5000, debug=False)

def main():
    if not check_admin():
        print("Cette application nécessite des privilèges administratifs.")
        sys.exit(1)

    # Démarrer le serveur Flask dans un processus séparé
    web_server_process = multiprocessing.Process(target=start_web_server)
    web_server_process.start()

    app = QApplication(sys.argv)
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))  # Charger les variables d'environnement
    
    try:
        auth_manager = AuthManager()
        auth_manager.initialize_database()
        
        # Vérifier si "Rester connecté" est activé et les informations sont valides
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        saved_username = os.getenv("SAVED_USERNAME", "")
        saved_password = os.getenv("SAVED_PASSWORD", "")
        stay_logged_in = os.getenv("STAY_LOGGED_IN", "false") == "true"

        if stay_logged_in and saved_username and saved_password:
            if auth_manager.authenticate(saved_username, saved_password):
                main_window = MainWindow()
                
                # Appliquer les préférences utilisateur
                if os.getenv("IS_FULLSCREEN", "false") == "true":
                    main_window.showFullScreen()
                else:
                    main_window.show()
                
                font_size = int(os.getenv("FONT_SIZE", 12))
                main_window.setFont(QFont("", font_size))
                
                sys.exit(app.exec())
        
        # Si "Rester connecté" n'est pas activé ou les informations sont invalides
        login_window = LoginWindow(auth_manager)
    except Exception as e:
        print(f"Erreur lors de l'initialisation : {e}")
        sys.exit(1)
    
    if login_window.exec() == LoginWindow.DialogCode.Accepted:
        main_window = MainWindow()
        
        # Appliquer les préférences utilisateur
        if os.getenv("IS_FULLSCREEN", "false") == "true":
            main_window.showFullScreen()
        else:
            main_window.show()
        
        font_size = int(os.getenv("FONT_SIZE", 12))
        main_window.setFont(QFont("", font_size))
        
        sys.exit(app.exec())
    else:
        sys.exit(0)

    # Arrêter le serveur Flask à la fermeture de l'application
    web_server_process.terminate()

if __name__ == "__main__":
    main()
