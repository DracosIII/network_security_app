import sys
import os

# Ajouter dynamiquement le chemin du projet au sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.append(project_root)

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import json
import sqlite3
import subprocess  # Pour exécuter des commandes système
from datetime import datetime
from windows_version.auth.auth_manager import AuthManager
import threading
import time
from windows_version.core.scanner_thread import NetworkScanThread
from windows_version.utils.arp_scanner import get_local_ip_prefixes

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = "your_secret_key"  # Remplacez par une clé secrète sécurisée
auth_manager = AuthManager()
# Utiliser 'threading' si eventlet n'est pas installé. Vous pouvez installer eventlet pour utiliser 'eventlet'
socketio = SocketIO(app, async_mode='threading')

# Chemins vers les fichiers de données
DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'attack_report.json')
DB_FILE = os.path.join(os.path.dirname(__file__), '..', 'actions.db')

scan_thread = None  # Thread global pour le scan réseau

@app.route("/", methods=["GET", "POST"])
def login():
    """Page de connexion."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if auth_manager.authenticate(username, password):
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Nom d'utilisateur ou mot de passe incorrect", "error")
    
    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Page d'inscription."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "error")
            return redirect(url_for("signup"))
        
        success, message = auth_manager.register_user(username, password)
        if success:
            flash("Inscription réussie. Vous pouvez maintenant vous connecter.", "success")
            return redirect(url_for("login"))
        else:
            flash(message, "error")
    
    return render_template("signup.html")

@app.route("/dashboard")
def dashboard():
    """Tableau de bord (accessible uniquement après connexion)."""
    if "username" not in session:
        return redirect(url_for("login"))
    
    return render_template("dashboard.html", username=session["username"])

# WebSocket : Envoi des données en temps réel
@socketio.on("request_data")
def handle_request_data():
    # Lis les données dynamiquement depuis ips.txt
    ips_file = os.path.join(os.path.dirname(__file__), '..', 'ips.txt')
    devices = []
    if os.path.exists(ips_file):
        with open(ips_file, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    device_name = parts[0]
                    ip_address = parts[1]
                    mac_address = parts[2]
                    ports_str = parts[3]
                    open_ports = ports_str if ports_str else ""
                    devices.append({
                        "name": device_name,
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "open_ports": open_ports
                    })
    emit("update_data", devices)

# WebSocket : Exécution de commandes
@socketio.on("execute_command")
def handle_execute_command(data):
    command = data.get("command")
    try:
        # Exécute la commande et retourne la sortie
        result = subprocess.check_output(command, shell=True, text=True)
        emit("command_result", {"status": "success", "output": result})
    except subprocess.CalledProcessError as e:
        emit("command_result", {"status": "error", "output": str(e)})

@app.route("/download")
def download():
    """Page de téléchargement."""
    return render_template("download.html")

@app.route("/logout")
def logout():
    """Déconnexion de l'utilisateur."""
    session.pop("username", None)
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("login"))

@app.route('/index')
def index():
    """Page d'accueil de l'interface web."""
    return render_template('index.html')

@app.route('/data')
def get_data():
    ips_file = os.path.join(os.path.dirname(__file__), '..', 'ips.txt')
    data = []
    if os.path.exists(ips_file):
        with open(ips_file, 'r', encoding='utf-8') as f:
            for line in f:
                # Format attendu : nom,ip,mac,port1;port2;port3
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    device_name = parts[0]
                    ip_address = parts[1]
                    mac_address = parts[2]
                    ports_str = parts[3]
                    open_ports = [int(p) for p in ports_str.split(';') if p.isdigit()] if ports_str else []
                    data.append({
                        "name": device_name,
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "open_ports": open_ports
                    })
    return jsonify(data)

@app.route('/actions')
def get_actions():
    """Retourne l'historique des actions sous forme JSON."""
    actions = fetch_actions_from_db()
    if not actions:
        return jsonify({"error": "Aucune action enregistrée"}), 404
    return jsonify(actions)

def fetch_actions_from_db():
    """Récupère les actions enregistrées dans la base de données."""
    if not os.path.exists(DB_FILE):
        return []

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT type, details, date FROM actions ORDER BY date DESC")
    actions = [{"type": row[0], "details": row[1], "date": row[2]} for row in cursor.fetchall()]
    conn.close()
    return actions

def log_action(action_type, details):
    """Enregistre une action et émet le log aux clients."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            details TEXT NOT NULL,
            date TEXT NOT NULL
        )
    ''')
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO actions (type, details, date) VALUES (?, ?, ?)",
                   (action_type, details, now))
    conn.commit()
    conn.close()
    log_msg = f"{now} - {action_type} : {details}"
    socketio.emit("log_update", {"message": log_msg})

@app.route('/execute_command', methods=['POST'])
def execute_command():
    global scan_thread
    command = request.form.get('command')
    attack_ips = request.form.get('attack_ips', '').strip()
    attack_timer = request.form.get('attack_timer', '').strip()
    network_prefix = request.form.get('network_prefix', '').strip()
    result = ""

    if not command:
        return jsonify({"result": "Commande vide."})

    if command == "start_scan":
        # Utilise le préfixe réseau choisi
        if not network_prefix:
            return jsonify({"result": "Veuillez sélectionner une carte réseau."})
        if scan_thread is None or not scan_thread.isRunning():
            def scan_finished():
                print("Scan réseau terminé (thread Flask).")
            scan_thread = NetworkScanThread(network_prefix=network_prefix)
            scan_thread.finished.connect(scan_finished)
            scan_thread.start()
            result = f"Scan réseau lancé sur {network_prefix}.x"
        else:
            result = "Un scan est déjà en cours."
    elif command == "stop_scan":
        if scan_thread and scan_thread.isRunning():
            scan_thread.stop()
            scan_thread.wait()
            result = "Scan réseau arrêté."
        else:
            result = "Aucun scan en cours."
    elif command == "start_attack":
        if not attack_ips:
            result = "Veuillez spécifier au moins une IP cible."
        else:
            ip_list = [ip.strip() for ip in attack_ips.split(';') if ip.strip()]
            try:
                duration = int(attack_timer)
                if duration < 1 or duration > 120:
                    return jsonify({"result": "Durée invalide (1-120s max)."})
            except Exception:
                return jsonify({"result": "Durée invalide."})

            def attack_thread(ip_list, duration):
                start_time = time.time()
                socketio.emit("log_update", {"message": f"Début de l'attaque sur {', '.join(ip_list)} pour {duration}s"})
                while time.time() - start_time < duration:
                    for ip in ip_list:
                        msg = f"Attaque en cours sur {ip} (t+{int(time.time()-start_time)}s)"
                        socketio.emit("log_update", {"message": msg})
                        time.sleep(1)
                socketio.emit("log_update", {"message": "Attaque terminée."})

            threading.Thread(target=attack_thread, args=(ip_list, duration), daemon=True).start()
            result = f"Attaque lancée sur : {', '.join(ip_list)} pour {duration}s"
    elif command == "stop_attack":
        result = "Arrêt d'attaque non implémenté."
    elif command == "start_sniffing":
        if not attack_ips:
            result = "Veuillez spécifier au moins une IP cible pour le sniffing."
        else:
            ip_list = [ip.strip() for ip in attack_ips.split(';') if ip.strip()]
            def sniffing_thread(ip_list):
                socketio.emit("log_update", {"message": f"Sniffing démarré sur : {', '.join(ip_list)}"})
                # Simulation d'événements sniffing (remplace par ta vraie logique)
                for i in range(10):
                    for ip in ip_list:
                        msg = f"Paquet capturé sur {ip} à t+{i}s"
                        socketio.emit("log_update", {"message": msg})
                    time.sleep(1)
                socketio.emit("log_update", {"message": "Sniffing terminé."})
            threading.Thread(target=sniffing_thread, args=(ip_list,), daemon=True).start()
            result = f"Sniffing lancé sur : {', '.join(ip_list)}"
    elif command == "stop_sniffing":
        result = "Arrêt du sniffing non implémenté."
    else:
        result = "Commande inconnue."

    return jsonify({"result": result})

@app.route('/network_prefixes')
def network_prefixes():
    return jsonify(get_local_ip_prefixes())

@socketio.on('request_update')
def handle_update_request():
    # Remplacer l'émission de connected_devices par la lecture dynamique de ips.txt
    ips_file = os.path.join(os.path.dirname(__file__), '..', 'ips.txt')
    devices = []
    if os.path.exists(ips_file):
        with open(ips_file, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    device_name = parts[0]
                    ip_address = parts[1]
                    mac_address = parts[2]
                    ports_str = parts[3]
                    open_ports = ports_str if ports_str else ""
                    devices.append({
                        "name": device_name,
                        "ip_address": ip_address,
                        "mac_address": mac_address,
                        "open_ports": open_ports
                    })
    emit('update_dashboard', devices)

if __name__ == '__main__':
    # Hébergement sur l'IP locale pour un accès via le réseau
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
