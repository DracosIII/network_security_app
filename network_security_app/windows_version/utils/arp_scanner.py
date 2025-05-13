# utils/arp_scanner.py
import subprocess
import re
import platform
import socket

def get_local_ip_prefixes():
    """Récupère les préfixes IP locaux disponibles."""
    prefixes = set()
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["ipconfig"], text=True, encoding='latin-1')
            current_interface_ips = []
            for line in output.splitlines():
                if "Carte réseau" in line or "Carte Ethernet" in line or "Wi-Fi" in line:
                    # Nouvelle interface, traite les IPs de l'interface précédente
                    for ip_info in current_interface_ips:
                        if "Adresse IPv4" in ip_info or "IPv4" in ip_info:
                            ip_address = ip_info.split(":")[1].strip()
                            prefixes.add(".".join(ip_address.split(".")[:3]))
                    current_interface_ips = []  # Réinitialise pour la nouvelle interface
                elif ":" in line:
                    current_interface_ips.append(line.strip())
            # Traite les IPs de la dernière interface
            for ip_info in current_interface_ips:
                if "Adresse IPv4" in ip_info or "IPv4" in ip_info:
                    ip_address = ip_info.split(":")[1].strip()
                    prefixes.add(".".join(ip_address.split(".")[:3]))

        elif platform.system() in ["Linux", "Darwin"]:
            output = subprocess.check_output(["ip", "addr"], text=True)
            for line in output.splitlines():
                if "inet " in line and "scope global" in line:
                    parts = line.split()
                    ip_address = parts[1].split("/")[0]
                    prefixes.add(".".join(ip_address.split(".")[:3]))
    except Exception as e:
        print(f"Erreur lors de la récupération des préfixes IP : {e}")
    return list(prefixes)

def get_device_name(ip):
    """
    Récupère le nom NetBIOS du périphérique à partir de son IP (Windows uniquement).
    """
    try:
        output = subprocess.check_output(["nbtstat", "-A", ip], text=True, encoding='latin-1')
        for line in output.splitlines():
            if "<00>" in line and "UNIQUE" in line:
                return line.split()[0].strip()
    except Exception:
        pass
    return "Inconnu"

def get_dns_name(ip):
    """
    Récupère le nom DNS (reverse DNS) du périphérique à partir de son IP.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Inconnu"

def scan_arp(ip_range):
    """Scanne la plage IP spécifiée en utilisant un broadcast ARP et récupère les noms NetBIOS et DNS."""
    active_hosts = []
    try:
        if platform.system() == "Windows":
            subprocess.run(["arp", "-d"], check=True)  # Effacer le cache ARP
            for i in range(1, 255):
                ip = f"{ip_range}.{i}"
                subprocess.run(["ping", "-n", "1", "-w", "100", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            output = subprocess.check_output(["arp", "-a"], text=True, encoding='latin-1')
            for line in output.splitlines():
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", line)
                if match:
                    ip = match.group(1)
                    netbios_name = get_device_name(ip)
                    dns_name = get_dns_name(ip)
                    active_hosts.append((ip, netbios_name, dns_name))
        elif platform.system() in ["Linux", "Darwin"]:
            for i in range(1, 255):
                ip = f"{ip_range}.{i}"
                subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            output = subprocess.check_output(["arp", "-n"], text=True)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) > 1 and re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parts[0]):
                    ip = parts[0]
                    dns_name = get_dns_name(ip)
                    active_hosts.append((ip, "Inconnu", dns_name))
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution de la commande ARP: {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")
    return active_hosts

def discover_local_hosts_arp():
    """Découvre les hôtes actifs sur tous les réseaux locaux détectés via ARP et affiche leurs noms."""
    local_ip_prefixes = get_local_ip_prefixes()
    all_active_hosts = []
    if not local_ip_prefixes:
        print("Impossible de déterminer les préfixes IP locaux.")
        return []
    for prefix in local_ip_prefixes:
        active_hosts = scan_arp(prefix)
        all_active_hosts.extend(active_hosts)
    return all_active_hosts

if __name__ == '__main__':
    hosts = discover_local_hosts_arp()
    if hosts:
        print("Hôtes actifs détectés sur le réseau local (via ARP) :")
        for ip, netbios_name, dns_name in hosts:
            print(f"- {ip} | NetBIOS : {netbios_name} | DNS : {dns_name}")
    else:
        print("Aucun hôte actif détecté sur le réseau local (via ARP).")