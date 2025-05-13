import sqlite3
from hashlib import sha256

class AuthManager:
    def __init__(self):
        self.conn = sqlite3.connect('users.db')  # Base de données SQLite pour les utilisateurs
        self.create_table()
    
    def create_table(self):
        """Crée la table users si elle n'existe pas."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        self.conn.commit()
    
    def initialize_database(self):
        """Initialise la base de données si elle n'existe pas."""
        try:
            self.create_table()
        except sqlite3.Error as e:
            print(f"Erreur lors de l'initialisation de la base de données : {e}")
    
    def _hash_password(self, password):
        """Hash le mot de passe avec SHA-256."""
        return sha256(password.encode('utf-8')).hexdigest()
    
    def user_exists(self, username):
        """Vérifie si un utilisateur existe."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", (username,))
        return cursor.fetchone()[0] == 1
    
    def authenticate(self, username, password):
        """Authentifie un utilisateur."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result and result[0] == self._hash_password(password)
        except sqlite3.Error as e:
            print(f"Erreur lors de l'authentification : {e}")
            return False
    
    def register_user(self, username, password):
        """Enregistre un nouvel utilisateur."""
        if self.user_exists(username):
            return False, "Nom d'utilisateur déjà pris"
            
        if len(password) < 8:
            return False, "Le mot de passe doit faire 8+ caractères"
            
        try:
            password_hash = self._hash_password(password)
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
            ''', (username, password_hash))
            self.conn.commit()
            return True, "Inscription réussie"
        except sqlite3.Error as e:
            return False, f"Erreur base de données: {str(e)}"
    
    def __del__(self):
        """Ferme la connexion à la base de données."""
        self.conn.close()
