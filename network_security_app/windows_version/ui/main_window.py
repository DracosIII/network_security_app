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
from utils.system_checks import check_admin, route_exists  # Importer la fonction route_existsfrom utils.system_checks import check_admin  # Importer la fonction pour vérifier les privilèges administratifs
import time
import threading
import scapy.all as scapy  # Ajout de Scapy pour le sniffing
import socket  # Ajout de l'importation du module socket
from web.server import log_action  # Importer la fonction log_action
from windows_version.utils.access_point import start_access_point, stop_access_point, is_hosted_network_supported, get_access_point_ip, get_network_adapters  # Importer les fonctions pour le point d'accès

class MainWindow(QMainWindow):
    # Signal pour mettre à jour l'interface utilisateur depuis les threads
    update_attack_output_signal = pyqtSignal(str)
    update_attack_progress_signal = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Security Tool")
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
        self.is_fullscreen = os.getenv("IS_FULLSCREEN", "false") == "true"  # Ajout de l'attribut is_fullscreen

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
        self.ip_input.setPlaceholderText("Entrez des IP séparées par ';' (ex: 192.168.1.1;192.168.1.241)")
        
        # Nouvel élément : liste déroulante pour choisir une IP cible détectée
        self.target_ip_combo = QComboBox()
        self.target_ip_combo.setPlaceholderText("Sélectionner une IP cible")
        
        # Bouton pour rafraîchir la liste des IP détectées (optionnel)
        self.refresh_ip_btn = QPushButton("Rafraîchir cible")
        self.refresh_ip_btn.clicked.connect(self.update_target_ip_options)
        
        self.duration_combo = QComboBox()
        self.duration_combo.addItems([f"{i}s" for i in range(10, 231, 10)])  
        self.duration_combo.setCurrentIndex(5)
        self.duration_label = QLabel("Durée de l'attaque :")
        
        self.attack_progress = QProgressBar()
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
        
        attack_layout.addWidget(QLabel("Adresses IP saisies :"))
        attack_layout.addWidget(self.ip_input)
        attack_layout.addWidget(QLabel("Ou choisissez une cible :"))
        attack_layout.addWidget(self.target_ip_combo)
        attack_layout.addWidget(self.refresh_ip_btn)
        attack_layout.addWidget(self.duration_label)
        attack_layout.addWidget(self.duration_combo)
        attack_layout.addWidget(self.attack_progress)
        attack_layout.addWidget(self.attack_output)
        attack_layout.addWidget(self.attack_btn)
        attack_layout.addWidget(self.stop_attack_btn)
        attack_layout.addWidget(self.sniff_btn)
        attack_layout.addWidget(self.stop_sniff_btn)
        
        self.tabs.addTab(attack_tab, "Attack")

        # Access Point Tab
        access_point_tab = QWidget()
        access_point_layout = QVBoxLayout(access_point_tab)

        self.adapter_label = QLabel("Sélectionnez une carte réseau :")
        self.adapter_combo = QComboBox()
        self.refresh_adapters()

        self.start_ap_btn = QPushButton("Démarrer le point d'accès")
        self.start_ap_btn.clicked.connect(self.start_access_point)

        self.stop_ap_btn = QPushButton("Arrêter le point d'accès")
        self.stop_ap_btn.clicked.connect(self.stop_access_point)

        self.ap_ip_label = QLabel("Adresse IP du point d'accès : Non disponible")
        self.update_access_point_ip()

        access_point_layout.addWidget(self.adapter_label)
        access_point_layout.addWidget(self.adapter_combo)
        access_point_layout.addWidget(self.start_ap_btn)
        access_point_layout.addWidget(self.stop_ap_btn)
        access_point_layout.addWidget(self.ap_ip_label)

        self.tabs.addTab(access_point_tab, "Point d'accès")

        self.tabs.currentChanged.connect(self.show_disclaimer)
        
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

        # Auto Start Access Point
        self.auto_start_ap_checkbox = QPushButton("Démarrage automatique du point d'accès")
        self.auto_start_ap_checkbox.setCheckable(True)
        self.auto_start_ap_checkbox.setChecked(os.getenv("AUTO_START_AP", "false") == "true")
        self.auto_start_ap_checkbox.clicked.connect(self.toggle_auto_start_ap)

        settings_layout.addWidget(self.stay_logged_in_checkbox)
        settings_layout.addWidget(self.fullscreen_checkbox)
        settings_layout.addWidget(self.theme_checkbox)
        settings_layout.addWidget(self.font_size_label)
        settings_layout.addWidget(self.font_size_slider)
        settings_layout.addWidget(self.auto_start_ap_checkbox)

        self.tabs.addTab(settings_tab, "Settings")
        
        layout.addWidget(self.tabs)

        # Démarrage automatique du point d'accès si activé
        if self.auto_start_ap_checkbox.isChecked():
            self.start_access_point()

    def apply_theme(self):
        """Applique le thème sombre ou clair."""
        if self.is_dark_theme:
            self.setStyleSheet("background-color: #2b2b2b; color: white;")
            self.theme_checkbox.setText("Thème clair")
        else:
            self.setStyleSheet("")
            self.theme_checkbox.setText("Thème sombre")

    def show_disclaimer(self, index):
        if self.tabs.tabText(index) == "Attack":
            QMessageBox.warning(
                self, 
                "Avertissement", 
                "En accédant à cet onglet, vous déclinez toute responsabilité liée à l'utilisation de cette fonctionnalité."
            )

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

    def update_results(self, result):
        # host, ports, device_name (nom réel)
        if len(result) == 3:
            host, ports, device_name = result
        else:
            host, ports = result
            device_name = host

        mac_address = f"00:1A:2B:{random.randint(10, 99):02X}:{random.randint(10, 99):02X}:{random.randint(10, 99):02X}"
        
        row_position = self.scan_table.rowCount()
        self.scan_table.insertRow(row_position)
        self.scan_table.setItem(row_position, 0, QTableWidgetItem(device_name))
        self.scan_table.setItem(row_position, 1, QTableWidgetItem(host))
        self.scan_table.setItem(row_position, 2, QTableWidgetItem(mac_address))
        if ports:
            open_ports = ", ".join(map(str, ports))
            self.scan_table.setItem(row_position, 3, QTableWidgetItem(open_ports))
        else:
            self.scan_table.setItem(row_position, 3, QTableWidgetItem("Aucun port ouvert"))

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.wait()
            QMessageBox.information(self, "Scan arrêté", "Le scan a été arrêté par l'utilisateur.")

    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        QMessageBox.information(self, "Scan terminé", "Le scan réseau est terminé.")

    def update_attack_output(self, message):
        """Met à jour la zone de texte de sortie de l'attaque."""
        self.attack_output.append(message)

    def update_attack_progress(self, value):
        """Met à jour la barre de progression de l'attaque."""
        self.attack_progress.setValue(value)

    def start_attack(self):
        """Lance une attaque DDoS simulée sur les périphériques sélectionnés ou spécifiés."""
        ip_list = self.get_ip_list()
        if not ip_list:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner des périphériques ou entrer des adresses IP valides.")
            return

        log_action("DDoS", f"IP(s) ciblée(s) : {', '.join(ip_list)}")  # Enregistrer l'action
        duration = int(self.duration_combo.currentText().replace("s", ""))  # Récupérer la durée sélectionnée
        self.attack_output.clear()
        self.attack_progress.setValue(0)  # Réinitialiser la barre de progression
        self.update_attack_output_signal.emit(f"Début de l'attaque DDoS pour {duration} secondes...")
        self.ddos_running = True
        self.stop_attack_btn.setEnabled(True)

        def ddos_target(ip, duration, progress_step):
            """Simule une attaque DDoS sur une cible pendant une durée donnée."""
            end_time = time.time() + duration
            while time.time() < end_time and self.ddos_running:
                try:
                    # Simuler une requête réseau (remplacez par une vraie requête si nécessaire)
                    time.sleep(0.05)  # Pause pour éviter une surcharge CPU
                    self.update_attack_output_signal.emit(f"Requête envoyée à {ip}")
                except Exception as e:
                    self.update_attack_output_signal.emit(f"Erreur lors de l'attaque sur {ip} : {e}")
                finally:
                    self.update_attack_progress_signal.emit(min(self.attack_progress.value() + progress_step, 100))

        threads = []
        progress_step = max(1, 100 // (len(ip_list) * duration * 20))  # Calculer l'incrément de progression
        for ip_address in ip_list:
            thread = threading.Thread(target=ddos_target, args=(ip_address, duration, progress_step))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        self.ddos_running = False
        self.stop_attack_btn.setEnabled(False)
        self.update_attack_progress_signal.emit(100)  # Assurer que la progression atteint 100%
        self.update_attack_output_signal.emit("Attaque DDoS terminée.")

    def stop_attack(self):
        """Arrête l'attaque DDoS."""
        self.ddos_running = False
        self.update_attack_output_signal.emit("Attaque DDoS arrêtée par l'utilisateur.")

    def start_sniffing(self):
        """Lance le sniffing sur les périphériques sélectionnés ou spécifiés."""
        if not check_admin():
            QMessageBox.critical(self, "Erreur", "Cette opération nécessite des privilèges administratifs.")
            return

        ip_list = self.get_ip_list()
        if not ip_list:
            QMessageBox.warning(self, "Erreur", "Veuillez sélectionner des périphériques ou entrer des adresses IP valides.")
            return

        log_action("Sniffing", f"IP(s) surveillée(s) : {', '.join(ip_list)}")  # Enregistrer l'action
        self.sniffing_running = True
        self.stop_sniff_btn.setEnabled(True)
        self.attack_output.append("Début du sniffing...")

        def sniff_packets(packet):
            """Capture et affiche les paquets sniffés."""
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                src_name = self.get_device_name(src)
                dst_name = self.get_device_name(dst)
                self.attack_output.append(f"Paquet capturé : {src_name} ({src}) -> {dst_name} ({dst})")

        def configure_gateway(ip_list):
            """Configure la passerelle pour rediriger le trafic."""
            for ip_address in ip_list:
                if not self.sniffing_running:
                    break
                try:
                    if os.name == "nt":  # Windows
                        subprocess.run(["route", "add", ip_address, "192.168.1.1"], capture_output=True, text=True, check=True)
                    else:  # Linux/Mac
                        subprocess.run(["sudo", "ip", "route", "add", ip_address, "via", "192.168.1.1"], capture_output=True, text=True, check=True)
                    self.attack_output.append(f"Passerelle configurée pour {ip_address}.")
                except subprocess.CalledProcessError as e:
                    self.attack_output.append(f"Erreur lors de la configuration de la passerelle pour {ip_address}: {e.stderr.strip()}")
                except Exception as e:
                    self.attack_output.append(f"Erreur inattendue pour {ip_address}: {e}")

        # Configurer la passerelle
        configure_gateway(ip_list)

        # Lancer le sniffing
        self.sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=sniff_packets, stop_filter=lambda _: not self.sniffing_running))
        self.sniff_thread.start()

    def stop_sniffing(self):
        """Arrête le sniffing."""
        self.sniffing_running = False
        self.stop_sniff_btn.setEnabled(False)
        self.attack_output.append("Sniffing arrêté par l'utilisateur.")

    def get_device_name(self, ip):
        """Récupère le nom du périphérique à partir de l'adresse IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Inconnu"

    def get_ip_list(self):
        """Récupère la liste des IP à attaquer ou surveiller.
           Priorité à l'IP sélectionnée dans target_ip_combo si présente."""
        # Si une IP est sélectionnée dans la liste déroulante, on l'utilise
        if self.target_ip_combo.currentText():
            return [self.target_ip_combo.currentText()]
        # Sinon, on utilise la sélection dans le tableau
        ip_list = []
        selected_rows = self.scan_table.selectionModel().selectedRows()
        for row in selected_rows:
            ip_list.append(self.scan_table.item(row.row(), 1).text())
        # Et on ajoute les IP saisies manuellement
        manual_ips = self.ip_input.text().strip()
        if manual_ips:
            ip_list.extend([ip.strip() for ip in manual_ips.split(";") if ip.strip()])
        
        return ip_list

    def toggle_stay_logged_in(self):
        self.stay_logged_in = self.stay_logged_in_checkbox.isChecked()
        self.save_preference("STAY_LOGGED_IN", "true" if self.stay_logged_in else "false")
        QMessageBox.information(self, "Paramètre modifié", f"Rester connecté : {'Activé' if self.stay_logged_in else 'Désactivé'}")

    def toggle_fullscreen(self):
        self.is_fullscreen = self.fullscreen_checkbox.isChecked()
        self.save_preference("IS_FULLSCREEN", "true" if self.is_fullscreen else "false")  # Sauvegarde de l'état plein écran
        if self.is_fullscreen:
            self.showFullScreen()
        else:
            self.showNormal()
        QMessageBox.information(self, "Paramètre modifié", f"Mode plein écran : {'Activé' if self.is_fullscreen else 'Désactivé'}")

    def toggle_theme(self):
        """Bascule entre le thème sombre et clair."""
        self.is_dark_theme = not self.is_dark_theme
        self.save_preference("THEME", "dark" if self.is_dark_theme else "light")
        self.apply_theme()
        QMessageBox.information(self, "Paramètre modifié", f"Thème : {'Sombre' if self.is_dark_theme else 'Clair'}")

    def change_font_size(self, value):
        self.font_size = value
        self.save_preference("FONT_SIZE", str(self.font_size))
        self.font_size_label.setText(f"Taille de la police : {self.font_size}")
        font = QFont()
        font.setPointSize(self.font_size)
        self.setFont(font)
        QMessageBox.information(self, "Paramètre modifié", f"Taille de la police : {self.font_size}")

    def update_access_point_ip(self):
        """Met à jour l'adresse IP affichée pour le point d'accès."""
        ip = get_access_point_ip()
        if ip:
            self.ap_ip_label.setText(f"Adresse IP du point d'accès : {ip}")
        else:
            self.ap_ip_label.setText("Adresse IP du point d'accès : Non disponible")

    def start_access_point(self):
        """Démarre le point d'accès avec le nom d'utilisateur, le mot de passe et la carte réseau sélectionnée."""
        adapter_name = self.adapter_combo.currentText()
        if not is_hosted_network_supported(adapter_name):
            QMessageBox.critical(self, "Erreur", f"Le réseau hébergé n'est pas pris en charge par la carte réseau '{adapter_name}'.")
            return

        username = os.getenv("SAVED_USERNAME", "default_ssid")
        password = os.getenv("SAVED_PASSWORD", "default_password")
        if len(password) < 8:
            QMessageBox.warning(self, "Erreur", "Le mot de passe doit contenir au moins 8 caractères.")
            return
        if start_access_point(username, password, adapter_name):
            QMessageBox.information(self, "Succès", f"Point d'accès démarré : {username}")
            self.update_access_point_ip()
        else:
            QMessageBox.critical(self, "Erreur", "Impossible de démarrer le point d'accès.")

    def stop_access_point(self):
        """Arrête le point d'accès."""
        if stop_access_point():
            QMessageBox.information(self, "Succès", "Point d'accès arrêté.")
            self.update_access_point_ip()
        else:
            QMessageBox.critical(self, "Erreur", "Impossible d'arrêter le point d'accès.")

    def toggle_auto_start_ap(self):
        """Active ou désactive le démarrage automatique du point d'accès."""
        auto_start = self.auto_start_ap_checkbox.isChecked()
        self.save_preference("AUTO_START_AP", "true" if auto_start else "false")
        QMessageBox.information(self, "Paramètre modifié", f"Démarrage automatique du point d'accès : {'Activé' if auto_start else 'Désactivé'}")

    def refresh_adapters(self):
        """Met à jour la liste des cartes réseau disponibles."""
        self.adapter_combo.clear()
        adapters = get_network_adapters()
        if adapters:
            self.adapter_combo.addItems(adapters)
        else:
            self.adapter_combo.addItem("Aucune carte réseau détectée")

    def update_target_ip_options(self):
        """Rafraîchit la liste déroulante avec les IP issues des résultats du scan."""
        self.target_ip_combo.clear()
        for row in range(self.scan_table.rowCount()):
            ip = self.scan_table.item(row, 1).text()
            self.target_ip_combo.addItem(ip)