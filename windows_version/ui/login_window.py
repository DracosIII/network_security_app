from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from ui.signup_window import SignupWindow

class LoginWindow(QDialog):
    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.setWindowTitle("Login")
        self.setModal(True)  
        
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
    
    def attempt_login(self):
        """Handle login attempt"""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if self.auth_manager.authenticate(username, password):
            self.accept() 
        else:
            QMessageBox.warning(self, "Erreur", "Nom d'utilisateur ou mot de passe incorrect")
            self.username_input.clear()
            self.password_input.clear()
    
    def show_signup(self):
        signup_window = SignupWindow(self.auth_manager)
        if signup_window.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Succès", "Compte créé avec succès! Vous pouvez maintenant vous connecter.")