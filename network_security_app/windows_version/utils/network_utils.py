import socket
import concurrent.futures
from time import time 
from typing import List, Tuple

class NetworkScanner:
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.active_hosts = []
    
    def scan_port(self, host: str, port: int) -> bool:
        """Scan un port individuel"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((host, port))
                return result == 0
        except Exception as e:
            print(f"Erreur réseau : {e}")
            return False
    
    def scan_host(self, host: str, ports: List[int]) -> List[Tuple[int, bool]]:
        """Scan plusieurs ports sur un hôte avec threading"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = executor.map(lambda p: (p, self.scan_port(host, p)), ports)
            return list(results)
    
    def fast_ping_sweep(self, network_prefix: str, start: int = 1, end: int = 254) -> List[str]:
        """Découverte rapide d'hôtes actifs (optimisée)"""
        active = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._quick_ping, f"{network_prefix}.{i}"): i for i in range(start, end + 1)
            }
            active = [future.result() for future in concurrent.futures.as_completed(futures) if future.result()]
        return active
    
    def _quick_ping(self, ip: str) -> bool:
        """Vérification rapide de disponibilité"""
        try:
            socket.gethostbyaddr(ip)
            return True
        except Exception as e:
            print(f"Erreur réseau : {e}")
            return False
