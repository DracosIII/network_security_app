import subprocess
import platform
from multiprocessing import Pool  # Importer Pool pour la gestion des processus

class FirewallManager:
    def __init__(self):
        self.os_type = platform.system().lower()
        
    def block_ip(self, ip):
        """Bloque une IP spécifique."""
        if self.os_type == "linux":
            try:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du blocage de l'IP {ip} : {e}")
                return False
        elif self.os_type == "windows":
            try:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=Block_{ip}', f'dir=in', f'action=block', f'remoteip={ip}'], check=True)
                print(f"IP {ip} bloquée avec succès.")
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du blocage de l'IP {ip} : {e}")
                return False
        else:
            print("Cette méthode est uniquement implémentée pour Linux et Windows.")
            return False
            
    def secure_port(self, port, protocol='tcp'):
        """Bloque un port spécifique."""
        if self.os_type == "linux":
            try:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', protocol, '--dport', str(port), '-j', 'DROP'], check=True)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du blocage du port {port} : {e}")
                return False
        elif self.os_type == "windows":
            try:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name=Block_Port_{port}', f'dir=in', f'action=block', f'protocol={protocol}', f'localport={port}'], check=True)
                print(f"Port {port}/{protocol} bloqué avec succès.")
                return True
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du blocage du port {port} : {e}")
                return False
        else:
            print("Cette méthode est uniquement implémentée pour Linux et Windows.")
            return False
            
    def apply_multiple_rules(self, rules):
        """Applique plusieurs règles en parallèle."""
        valid_rules = [rule for rule in rules if self._validate_rule(rule)]
        if not valid_rules:
            print("Aucune règle valide à appliquer.")
            return False

        try:
            with Pool() as pool:
                results = pool.map(self._apply_rule, valid_rules)
            return all(results)
        except Exception as e:
            print(f"Erreur lors de l'application des règles : {e}")
            return False
        
    def _apply_rule(self, rule):
        """Applique une règle individuelle."""
        if rule['type'] == 'block_ip':
            return self.block_ip(rule['ip'])
        elif rule['type'] == 'secure_port':
            return self.secure_port(rule['port'], rule.get('protocol', 'tcp'))
        return False

    def _validate_rule(self, rule):
        """Valide une règle avant de l'appliquer."""
        if rule['type'] == 'block_ip' and 'ip' in rule:
            return True
        if rule['type'] == 'secure_port' and 'port' in rule:
            return True
        print(f"Règle invalide : {rule}")
        return False
