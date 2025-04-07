import subprocess
from multiprocessing import Pool
from ..utils.network_utils import detect_os

class FirewallManager:
    def __init__(self):
        self.os_type = detect_os()
        
    def block_ip(self, ip):
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                           'name="Block IP"', 'dir=in', 'action=block',
                           'remoteip='+ip], check=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def secure_port(self, port, protocol='tcp'):
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                          'name="Block Port"', 'dir=in', 'action=block',
                          'protocol='+protocol.upper(), 'localport='+str(port)], check=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def apply_multiple_rules(self, rules):
        with Pool() as pool:
            results = pool.map(self._apply_rule, rules)
        return all(results)
        
    def _apply_rule(self, rule):
        if rule['type'] == 'block_ip':
            return self.block_ip(rule['ip'])
        elif rule['type'] == 'secure_port':
            return self.secure_port(rule['port'], rule.get('protocol', 'tcp'))
        return False
