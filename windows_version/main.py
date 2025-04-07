import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow, QDialog, QPushButton
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from ui.login_window import LoginWindow 
from auth.auth_manager import AuthManager
from ui.main_window import MainWindow

def main():
    app = QApplication(sys.argv)
    
    auth_manager = AuthManager()
    login_window = LoginWindow(auth_manager)
    
    if login_window.exec() == LoginWindow.DialogCode.Accepted:
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)
        


if __name__ == "__main__":
    main()
