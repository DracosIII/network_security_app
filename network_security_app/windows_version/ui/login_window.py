from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from ui.signup_window import SignupWindow
from dotenv import load_dotenv, set_key
import os

class LoginWindow(QDialog):
    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.setWindowTitle("Login")
        self.setModal(True)
        self.load_preferences()  # Charger les préférences utilisateur
        
        layout = QVBoxLayout()
        
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_button = QPushButton("Login")
        self.signup_button = QPushButton("Créer un compte") 
        
        layout.addWidget(QLabel("Username:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.signup_button)  
        
        self.setLayout(layout)
        
        # Connect signals
        self.login_button.clicked.connect(self.attempt_login)
        self.signup_button.clicked.connect(self.show_signup)  
    
    def load_preferences(self):
        """Charge les préférences utilisateur depuis le fichier .env."""
        env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
        load_dotenv(env_path)
        saved_username = os.getenv("SAVED_USERNAME", "")
        saved_password = os.getenv("SAVED_PASSWORD", "")
        stay_logged_in = os.getenv("STAY_LOGGED_IN", "false") == "true"

        if stay_logged_in and saved_username and saved_password:
            if self.auth_manager.authenticate(saved_username, saved_password):
                self.accept()

    def attempt_login(self):
        """Handle login attempt"""
        username = self.username_input.text()
        password = self.password_input.text()  # Correction : utiliser le champ password_input
        
        if not username or not password:
            QMessageBox.warning(self, "Erreur", "Veuillez remplir tous les champs")
            return
        
        if self.auth_manager.authenticate(username, password):
            # Sauvegarder les informations si "Rester connecté" est activé
            if os.getenv("STAY_LOGGED_IN", "false") == "true":
                env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
                set_key(env_path, "SAVED_USERNAME", username)
                set_key(env_path, "SAVED_PASSWORD", password)
            self.accept()
        else:
            QMessageBox.warning(self, "Erreur", "Nom d'utilisateur ou mot de passe incorrect")
            self.username_input.clear()
            self.password_input.clear()
    
    def show_signup(self):
        signup_window = SignupWindow(self.auth_manager)
        if signup_window.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Succès", "Compte créé avec succès! Vous pouvez maintenant vous connecter.")