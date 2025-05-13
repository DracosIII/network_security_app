import subprocess
import platform

class FirewallManager:
    def __init__(self):
        self.os_type = platform.system().lower()

    def block_ip(self, ip):
        """Bloque une IP spécifique."""
        if self.os_type == "linux":
            try:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                print(f"IP {ip} bloquée avec succès.")
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du blocage de l'IP {ip} : {e}")
                return False
            except FileNotFoundError:
                print("Erreur : La commande 'iptables' n'est pas disponible. Assurez-vous qu'elle est installée.")
                return False
        else:
            print("Cette méthode est uniquement implémentée pour Linux.")
            return False

    def secure_port(self, port, protocol='tcp'):
        """Bloque un port spécifique."""
        if self.os_type == "linux":
            try:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', protocol, '--dport', str(port), '-j', 'DROP'], check=True)
                print(f"Port {port}/{protocol} bloqué avec succès.")
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du blocage du port {port} : {e}")
                return False
            except FileNotFoundError:
                print("Erreur : La commande 'iptables' n'est pas disponible. Assurez-vous qu'elle est installée.")
                return False
        else:
            print("Cette méthode est uniquement implémentée pour Linux.")
            return False
