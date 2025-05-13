import socket
import concurrent.futures
from typing import List, Tuple
import ipaddress
import os
import platform
import subprocess

class NetworkScanner:

    def __init__(self, timeout: float = 0.5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self._should_stop = False

    def _get_local_network_prefix(self) -> str:
        """Détecte automatiquement le préfixe réseau (ex: 192.168.1)"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            parts = local_ip.split('.')
            return '.'.join(parts[:3])  # ex: "192.168.1"
        except Exception as e:
            print(f"Erreur pour obtenir l'IP locale : {e}")
            return "192.168.1"  # fallback

    def discover_hosts(self, network_prefix: str = None) -> List[str]:
        """Détecte les hôtes actifs sur le réseau"""
        if not network_prefix:
            network_prefix = self._get_local_network_prefix()

        active_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._ping_host, f"{network_prefix}.{i}"): i
                for i in range(1, 255)
            }

            for future in concurrent.futures.as_completed(futures):
                if self._should_stop:
                    break  # Arrête les threads en cours
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
                    break  # Arrête les threads en cours
                if is_open:
                    open_ports.append(port)
        return open_ports

    def _ping_host(self, ip: str) -> Tuple[str, bool]:
        """Vérifie si un hôte répond (utilise un ping ICMP pour plus de fiabilité)."""
        try:
            if platform.system().lower() == "windows":
                command = ["ping", "-n", "1", "-w", "1000", ip]
            else:  # Linux/Mac
                command = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ip, result.returncode == 0
        except Exception as e:
            print(f"Erreur lors du ping de {ip} : {e}")
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
