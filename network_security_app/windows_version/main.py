import sys
import os
import ctypes
import multiprocessing
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QFontDatabase
from dotenv import load_dotenv, set_key

os.environ["QT_SCALE_FACTOR"] = "1"
os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
os.environ["QT_FONT_DPI"] = "96" 

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.append(project_root)

from web.server import app  #serveur Flask
from ui.login_window import LoginWindow
from auth.auth_manager import AuthManager
from ui.main_window import MainWindow

def save_env_variable(key, value):
    """Sauvegarde une variable dans le fichier .env."""
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    set_key(env_path, key, value)

def ensure_admin():
    """Vérifie si l'application est lancée en tant qu'administrateur."""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Redémarrage en mode administrateur...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
            sys.exit(0)
    except Exception as e:
        print(f"Erreur lors de la vérification des privilèges administratifs : {e}")
        sys.exit(1)

def start_web_server():
    """Démarre le serveur Flask dans un processus séparé."""
    app.run(host='0.0.0.0', port=5000, debug=False)

def main():
    # Vérification des fichiers statiques essentiels
    static_dir = os.path.join(project_root, 'web', 'static')
    logo_path = os.path.join(static_dir, 'logo.png')
    favicon_path = os.path.join(static_dir, 'favicon.ico')
    if not os.path.exists(logo_path):
        print(f"AVERTISSEMENT : Le fichier logo.png est manquant dans {static_dir}")
    if not os.path.exists(favicon_path):
        print(f"AVERTISSEMENT : Le fichier favicon.ico est manquant dans {static_dir}")

    ensure_admin()  # Vérifie les admin

    # Demmarer serveur Flask 
    web_server_process = multiprocessing.Process(target=start_web_server)
    web_server_process.start()

    try:
        app = QApplication(sys.argv)

        # Définir une police par défaut
        QFontDatabase.addApplicationFont("C:/Windows/Fonts/Arial.ttf") 
        app.setFont(QFont("Arial", 12))  

        load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))  
        
        auth_manager = AuthManager()
        auth_manager.initialize_database()
        
        # Vérifier variables env
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
        
        # Si "Rester connecté" n est pas activé ou les informations sont invalides
        login_window = LoginWindow(auth_manager)
        if login_window.exec() == LoginWindow.DialogCode.Accepted:
            main_window = MainWindow()
            
            # Appliquer préférences user
            if os.getenv("IS_FULLSCREEN", "false") == "true":
                main_window.showFullScreen()
            else:
                main_window.show()
            
            font_size = int(os.getenv("FONT_SIZE", 12))
            main_window.setFont(QFont("", font_size))
            
            sys.exit(app.exec())
    except Exception as e:
        print(f"Erreur lors de l'initialisation : {e}")
    finally:
        # Arrêter serveur Flask à fermeture de l'app
        if web_server_process.is_alive():
            web_server_process.terminate()
            web_server_process.join()

if __name__ == "__main__":
    main()
