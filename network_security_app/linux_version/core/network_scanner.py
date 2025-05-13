import socket
import concurrent.futures
from typing import List, Tuple
import subprocess

class NetworkScanner:
    def __init__(self, timeout: float = 0.5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    def discover_hosts(self, network_prefix: str) -> List[str]:
        """Détecte les hôtes actifs sur le réseau."""
        active_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._ping_host, f"{network_prefix}.{i}"): i
                for i in range(1, 255)
            }

            for future in concurrent.futures.as_completed(futures):
                host, is_active = future.result()
                if is_active:
                    active_hosts.append(host)
        return active_hosts

    def _ping_host(self, ip: str) -> Tuple[str, bool]:
        """Vérifie si un hôte répond."""
        try:
            command = ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ip, result.returncode == 0
        except Exception as e:
            print(f"Erreur lors du ping de {ip} : {e}")
            return ip, False
