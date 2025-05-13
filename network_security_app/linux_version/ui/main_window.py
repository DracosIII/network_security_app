import json
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget, 
                            QTextEdit, QPushButton, QProgressBar, QLabel, QMessageBox, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QSlider, QLineEdit)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from core.scanner_thread import NetworkScanThread
from utils.arp_scanner import get_local_ip_prefixes, scan_arp
import random
import os
import subprocess
from dotenv import load_dotenv, set_key
from utils.system_checks import check_admin, route_exists
import time
import threading
import scapy.all as scapy
import socket
from linux_version.utils.access_point import start_access_point, stop_access_point  # Importer les fonctions pour le point d'accès

class MainWindow(QMainWindow):
    # Signal pour mettre à jour l'interface utilisateur depuis les threads
    update_attack_output_signal = pyqtSignal(str)
    update_attack_progress_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Security Tool (Linux)")
        self.setMinimumSize(800, 600)
        self.scan_thread = None
        self.ddos_running = False  # Indicateur pour arrêter le DDoS
        self.sniffing_running = False  # Indicateur pour arrêter le sniffing
        self.load_preferences()  # Charger les préférences utilisateur
        self._init_ui()
        self.apply_theme()  # Appliquer le thème chargé

        # Appliquer les préférences utilisateur
        if self.is_fullscreen:
            self.showFullScreen()
        else:
            self.showNormal()
        
        font = QFont()
        font.setPointSize(self.font_size)
        self.setFont(font)

        # Connecter les signaux aux méthodes de mise à jour
        self.update_attack_output_signal.connect(self.update_attack_output)
        self.update_attack_progress_signal.connect(self.update_attack_progress)

    def load_preferences(self):
        """Charge les préférences utilisateur depuis le fichier .env."""
        env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
        load_dotenv(env_path)
        self.is_dark_theme = os.getenv("THEME", "dark") == "dark"
        self.font_size = int(os.getenv("FONT_SIZE", 12))
        self.stay_logged_in = os.getenv("STAY_LOGGED_IN", "false") == "true"
        self.is_fullscreen = os.getenv("IS_FULLSCREEN", "false") == "true"

    def save_preference(self, key, value):
        """Sauvegarde une préférence utilisateur dans le fichier .env."""
        env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
        set_key(env_path, key, value)

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.tabs = QTabWidget()
        
        # Scan Tab
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        
        self.network_interface_label = QLabel("Sélectionnez une carte réseau :")
        self.network_interface_combo = QComboBox()
        self.network_interface_combo.addItems(get_local_ip_prefixes())
        
        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(4)  # Ajouter une colonne pour les ports ouverts
        self.scan_table.setHorizontalHeaderLabels(["Nom du périphérique", "Adresse IP", "Adresse MAC", "Ports ouverts"])
        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.scan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        
        self.progress = QProgressBar()
        
        scan_layout.addWidget(self.network_interface_label)
        scan_layout.addWidget(self.network_interface_combo)
        scan_layout.addWidget(self.scan_table)
        scan_layout.addWidget(self.scan_btn)
        scan_layout.addWidget(self.stop_btn)
        scan_layout.addWidget(self.progress)
        
        self.tabs.addTab(scan_tab, "Network Scan")
        
        # Attack Tab
        attack_tab = QWidget()
        attack_layout = QVBoxLayout(attack_tab)
        
        self.attack_output = QTextEdit()
        self.attack_output.setReadOnly(True)
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Entrez les IP des hôtes (ex: 192.168.1.1 ; 192.168.1.241)")
        
        self.duration_combo = QComboBox()
        self.duration_combo.addItems([f"{i}s" for i in range(10, 231, 10)])  # Durées de 10s à 220s par pas de 10
        self.duration_combo.setCurrentIndex(5)  # Par défaut, 60 secondes
        self.duration_label = QLabel("Durée de l'attaque :")
        
        self.attack_progress = QProgressBar()  # Barre de progression pour l'attaque
        self.attack_progress.setValue(0)
        
        self.attack_btn = QPushButton("Lancer l'attaque")
        self.attack_btn.clicked.connect(self.start_attack)
        
        self.stop_attack_btn = QPushButton("Arrêter l'attaque")
        self.stop_attack_btn.setEnabled(False)
        self.stop_attack_btn.clicked.connect(self.stop_attack)

        self.sniff_btn = QPushButton("Lancer le sniffing")
        self.sniff_btn.clicked.connect(self.start_sniffing)

        self.stop_sniff_btn = QPushButton("Arrêter le sniffing")
        self.stop_sniff_btn.setEnabled(False)
        self.stop_sniff_btn.clicked.connect(self.stop_sniffing)
        
        attack_layout.addWidget(QLabel("Adresses IP des hôtes :"))
        attack_layout.addWidget(self.ip_input)
        attack_layout.addWidget(self.duration_label)
        attack_layout.addWidget(self.duration_combo)
        attack_layout.addWidget(self.attack_progress)  # Ajout de la barre de progression
        attack_layout.addWidget(self.attack_output)
        attack_layout.addWidget(self.attack_btn)
        attack_layout.addWidget(self.stop_attack_btn)
        attack_layout.addWidget(self.sniff_btn)
        attack_layout.addWidget(self.stop_sniff_btn)
        
        self.tabs.addTab(attack_tab, "Attack")
        self.tabs.currentChanged.connect(self.show_disclaimer)
        
        # Access Point Tab
        access_point_tab = QWidget()
        access_point_layout = QVBoxLayout(access_point_tab)

        self.start_ap_btn = QPushButton("Démarrer le point d'accès")
        self.start_ap_btn.clicked.connect(self.start_access_point)

        self.stop_ap_btn = QPushButton("Arrêter le point d'accès")
        self.stop_ap_btn.clicked.connect(self.stop_access_point)

        access_point_layout.addWidget(self.start_ap_btn)
        access_point_layout.addWidget(self.stop_ap_btn)

        self.tabs.addTab(access_point_tab, "Point d'accès")
        
        # Settings Tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Stay Logged In
        self.stay_logged_in_checkbox = QPushButton("Rester connecté")
        self.stay_logged_in_checkbox.setCheckable(True)
        self.stay_logged_in_checkbox.setChecked(self.stay_logged_in)
        self.stay_logged_in_checkbox.clicked.connect(self.toggle_stay_logged_in)
        
        # Fullscreen Mode
        self.fullscreen_checkbox = QPushButton("Mode plein écran")
        self.fullscreen_checkbox.setCheckable(True)
        self.fullscreen_checkbox.setChecked(self.is_fullscreen)
        self.fullscreen_checkbox.clicked.connect(self.toggle_fullscreen)
        
        # Dark/Light Theme
        self.theme_checkbox = QPushButton("Thème clair")  # Texte mis à jour pour refléter l'action
        self.theme_checkbox.setCheckable(True)
        self.theme_checkbox.setChecked(not self.is_dark_theme)
        self.theme_checkbox.clicked.connect(self.toggle_theme)
        
        # Font Size
        self.font_size_label = QLabel(f"Taille de la police : {self.font_size}")
        self.font_size_slider = QSlider(Qt.Orientation.Horizontal)
        self.font_size_slider.setRange(8, 24)
        self.font_size_slider.setValue(self.font_size)
        self.font_size_slider.valueChanged.connect(self.change_font_size)
        
        settings_layout.addWidget(self.stay_logged_in_checkbox)
        settings_layout.addWidget(self.fullscreen_checkbox)
        settings_layout.addWidget(self.theme_checkbox)
        settings_layout.addWidget(self.font_size_label)
        settings_layout.addWidget(self.font_size_slider)
        
        self.tabs.addTab(settings_tab, "Settings")
        
        layout.addWidget(self.tabs)

    def start_access_point(self):
        """Démarre le point d'accès avec le nom d'utilisateur et le mot de passe."""
        username = os.getenv("SAVED_USERNAME", "default_ssid")
        password = os.getenv("SAVED_PASSWORD", "default_password")
        if len(password) < 8:
            QMessageBox.warning(self, "Erreur", "Le mot de passe doit contenir au moins 8 caractères.")
            return
        start_access_point(username, password)

    def stop_access_point(self):
        """Arrête le point d'accès."""
        stop_access_point()

    def start_scan(self):
        self.scan_table.setRowCount(0)
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setValue(0)
        
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, "Scan en cours", "Un scan est déjà en cours")
            return
        
        selected_network_prefix = self.network_interface_combo.currentText()
        if not selected_network_prefix:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner une carte réseau valide.")
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            return

        self.scan_thread = NetworkScanThread(selected_network_prefix)
        self.scan_thread.result_signal.connect(self.update_results)
        self.scan_thread.progress_signal.connect(self.progress.setValue)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    # ...existing methods for scanning, attack, sniffing, and settings...
