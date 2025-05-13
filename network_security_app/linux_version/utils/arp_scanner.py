import subprocess
import re

def scan_arp(ip_range):
    """Scanne la plage IP spécifiée en utilisant un broadcast ARP."""
    active_hosts = []
    try:
        for i in range(1, 255):
            ip = f"{ip_range}.{i}"
            subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output = subprocess.check_output(["arp", "-n"], text=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) > 1 and re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parts[0]):
                ip = parts[0]
                active_hosts.append(ip)
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de la commande ARP: {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")
    return list(set(active_hosts))
