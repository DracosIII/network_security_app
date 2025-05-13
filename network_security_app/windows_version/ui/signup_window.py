from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, 
    QLineEdit, QPushButton, QMessageBox
)
from PyQt6.QtCore import Qt

class SignupWindow(QDialog):
    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.setWindowTitle("Créer un compte")
        self.setModal(True)
        self.setFixedSize(350, 250)
        
        layout = QVBoxLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choisissez un nom d'utilisateur")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Mot de passe (8 caractères minimum)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirmez le mot de passe")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.signup_button = QPushButton("S'inscrire")
        self.signup_button.clicked.connect(self.attempt_signup)
        
        layout.addWidget(QLabel("Nom d'utilisateur:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Mot de passe:"))
        layout.addWidget(self.password_input)
        layout.addWidget(QLabel("Confirmation:"))
        layout.addWidget(self.confirm_input)
        layout.addWidget(self.signup_button)
        
        self.setLayout(layout)
    
    def attempt_signup(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        # Validation
        if not username or not password or not confirm:
            QMessageBox.warning(self, "Champs manquants", "Tous les champs sont obligatoires")
            return
            
        if " " in username:
            QMessageBox.warning(self, "Erreur", "Le nom d'utilisateur ne peut pas contenir d'espaces")
            return

        if len(username) < 3:
            QMessageBox.warning(self, "Erreur", "Le nom d'utilisateur doit contenir au moins 3 caractères")
            return
            
        if password != confirm:
            QMessageBox.warning(self, "Erreur", "Les mots de passe ne correspondent pas")
            self.password_input.clear()
            self.confirm_input.clear()
            return
            
        success, message = self.auth_manager.register_user(username, password)
        
        if success:
            QMessageBox.information(self, "Succès", message)
            self.accept()
        else:
            QMessageBox.critical(self, "Erreur", message)
            self.username_input.clear()
            self.password_input.clear()
            self.confirm_input.clear()