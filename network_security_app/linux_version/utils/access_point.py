import os
import platform
import subprocess

def start_access_point(ssid, password):
    """Démarre un point d'accès local."""
    if platform.system().lower() == "windows":
        try:
            # Configurer le réseau hébergé
            subprocess.run(["netsh", "wlan", "set", "hostednetwork", "mode=allow", f"ssid={ssid}", f"key={password}"], check=True)
            # Démarrer le réseau hébergé
            subprocess.run(["netsh", "wlan", "start", "hostednetwork"], check=True)
            print(f"Point d'accès démarré : {ssid}")
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors du démarrage du point d'accès : {e}")
    elif platform.system().lower() == "linux":
        try:
            # Configurer et démarrer le point d'accès sur Linux
            subprocess.run(["nmcli", "dev", "wifi", "hotspot", "ifname", "wlan0", f"ssid={ssid}", f"password={password}"], check=True)
            print(f"Point d'accès démarré : {ssid}")
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors du démarrage du point d'accès : {e}")
    else:
        print("Le système d'exploitation n'est pas pris en charge.")

def stop_access_point():
    """Arrête le point d'accès local."""
    if platform.system().lower() == "windows":
        try:
            subprocess.run(["netsh", "wlan", "stop", "hostednetwork"], check=True)
            print("Point d'accès arrêté.")
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors de l'arrêt du point d'accès : {e}")
    elif platform.system().lower() == "linux":
        try:
            subprocess.run(["nmcli", "con", "down", "Hotspot"], check=True)
            print("Point d'accès arrêté.")
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors de l'arrêt du point d'accès : {e}")
    else:
        print("Le système d'exploitation n'est pas pris en charge.")
