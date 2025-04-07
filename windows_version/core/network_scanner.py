import socket
import concurrent.futures
from typing import List, Tuple

class NetworkScanner:
    print("scanning network...")
    def __init__(self, timeout: float = 0.5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self._should_stop = False

    def discover_hosts(self, network_prefix: str) -> List[str]:
        """Détecte les hôtes actifs sur le réseau"""
        active_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._ping_host, f"{network_prefix}.{i}"): i 
                for i in range(1, 255)
            }
            
            for future in concurrent.futures.as_completed(futures):
                if self._should_stop:
                    break
                host, is_active = future.result()
                if is_active:
                    active_hosts.append(host)
        return active_hosts
    def scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scanne les ports spécifiés sur un hôte"""
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(lambda p: (p, self._scan_port(host, p)), ports)
            
            for port, is_open in results:
                if self._should_stop:
                    break
                if is_open:
                    open_ports.append(port)
        return open_ports

    def _ping_host(self, ip: str) -> Tuple[str, bool]:
        """Vérifie si un hôte répond"""
        try:
            socket.gethostbyaddr(ip)
            return ip, True
        except:
            return ip, False

    def _scan_port(self, host: str, port: int) -> bool:
        """Scanne un port individuel"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((host, port)) == 0
        except:
            return False

    def stop(self):
        """Arrête les opérations en cours"""
        self._should_stop = True