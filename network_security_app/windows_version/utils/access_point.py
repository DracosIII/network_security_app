import subprocess
import re

def get_network_adapters():
    """
    Récupère la liste de toutes les cartes réseau disponibles sur le système.
    """
    adapters = []
    try:
        output = subprocess.check_output(["ipconfig", "/all"], text=True, encoding="latin-1")
        for line in output.splitlines():
            # Identifier les noms des cartes réseau
            if re.match(r"^[A-Za-z].*:$", line.strip()):
                adapter_name = line.strip().rstrip(":")
                adapters.append(adapter_name)
        return adapters
    except Exception as e:
        print(f"Erreur lors de la récupération des cartes réseau : {e}")
        return []

def is_hosted_network_supported(adapter_name):
    """
    Vérifie si le réseau hébergé est pris en charge par une carte réseau spécifique.
    """
    try:
        output = subprocess.check_output(["netsh", "wlan", "show", "drivers"], text=True, encoding="latin-1")
        return adapter_name in output and "Prise en charge du réseau hébergé : Oui" in output
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la vérification du support du réseau hébergé : {e}")
        return False

def get_access_point_ip():
    """
    Récupère l'adresse IPv4 de l'interface réseau utilisée pour le point d'accès.
    """
    try:
        output = subprocess.check_output(["ipconfig"], text=True, encoding="latin-1")
        interface_found = False
        for line in output.splitlines():
            if "Connexion au réseau local* 2" in line:  # Identifier l'interface réseau
                interface_found = True
            if interface_found and "Adresse IPv4" in line:
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if ip_match:
                    return ip_match.group(1)
    except Exception as e:
        print(f"Erreur lors de la récupération de l'adresse IP du point d'accès : {e}")
    return None

def start_access_point(ssid, password, adapter_name):
    """
    Démarre un point d'accès local sur Windows en utilisant une carte réseau spécifique.
    :param ssid: Nom du réseau Wi-Fi (SSID).
    :param password: Mot de passe du réseau (minimum 8 caractères).
    :param adapter_name: Nom de la carte réseau à utiliser.
    """
    if len(password) < 8:
        print("Erreur : Le mot de passe doit contenir au moins 8 caractères.")
        return False

    if not is_hosted_network_supported(adapter_name):
        print(f"Erreur : Le réseau hébergé n'est pas pris en charge par la carte réseau '{adapter_name}'.")
        return False

    try:
        # Configurer le réseau hébergé
        subprocess.run(
            ["netsh", "wlan", "set", "hostednetwork", "mode=allow", f"ssid={ssid}", f"key={password}"],
            check=True
        )
        # Démarrer le réseau hébergé
        subprocess.run(["netsh", "wlan", "start", "hostednetwork"], check=True)
        print(f"Point d'accès démarré avec succès : {ssid}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du démarrage du point d'accès : {e}")
        return False

def stop_access_point():
    """
    Arrête le point d'accès local sur Windows.
    """
    try:
        subprocess.run(["netsh", "wlan", "stop", "hostednetwork"], check=True)
        print("Point d'accès arrêté avec succès.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'arrêt du point d'accès : {e}")
        return False

def configure_access_point(ssid, password):
    """
    Configure le point d'accès local sans le démarrer.
    :param ssid: Nom du réseau Wi-Fi (SSID).
    :param password: Mot de passe du réseau (minimum 8 caractères).
    """
    if len(password) < 8:
        print("Erreur : Le mot de passe doit contenir au moins 8 caractères.")
        return False

    try:
        subprocess.run(
            ["netsh", "wlan", "set", "hostednetwork", "mode=allow", f"ssid={ssid}", f"key={password}"],
            check=True
        )
        print(f"Point d'accès configuré avec succès : {ssid}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de la configuration du point d'accès : {e}")
        return False
