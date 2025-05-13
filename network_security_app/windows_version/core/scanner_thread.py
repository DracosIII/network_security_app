from PyQt6.QtCore import QThread, pyqtSignal
from core.network_scanner import NetworkScanner
import concurrent.futures
import socket
import os
import random

class NetworkScanThread(QThread):
    result_signal = pyqtSignal(tuple)  # (host, ports, device_name)
    progress_signal = pyqtSignal(int)

    def __init__(self, network_prefix=None, max_threads=100):
        super().__init__()
        self.network_prefix = network_prefix
        self.max_threads = max_threads
        self._scanner = NetworkScanner(timeout=0.5, max_threads=max_threads)
        self._is_running = True

    def run(self):
        """Exécute la découverte des hôtes et le scan des ports."""
        try:
            # Découverte des hôtes actifs
            hosts = self._scanner.discover_hosts(self.network_prefix)
            total_hosts = len(hosts)
            scanned_ports = [22, 80, 443, 8080]  # Ports courants à scanner

            if total_hosts == 0:
                print("Aucun hôte détecté sur le réseau.")
                self.progress_signal.emit(100)
                return

            ips_file = os.path.join(os.path.dirname(__file__), '..', '..', 'ips.txt')
            # Nettoyer le fichier au début du scan
            with open(ips_file, 'w', encoding='utf-8'):
                pass

            # Scan des ports sur les hôtes détectés
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(self._scanner.scan_ports, host, scanned_ports): host for host in hosts
                }

                for index, future in enumerate(concurrent.futures.as_completed(futures)):
                    if not self._is_running:
                        break

                    host = futures[future]
                    try:
                        ports = future.result()
                        # Récupérer le vrai nom du périphérique (DNS)
                        try:
                            device_name = socket.gethostbyaddr(host)[0]
                        except Exception:
                            device_name = host
                        mac_address = "00:1A:2B:{:02X}:{:02X}:{:02X}".format(
                            random.randint(10, 99),
                            random.randint(10, 99),
                            random.randint(10, 99)
                        )
                        ports_str = ";".join(str(p) for p in ports) if ports else ""
                        # Ouvrir en mode ajout pour chaque résultat
                        with open(ips_file, 'a', encoding='utf-8') as f:
                            f.write(f"{device_name},{host},{mac_address},{ports_str}\n")
                        print(f"Hôte détecté : {host} ({device_name}), Ports ouverts : {ports}")
                        self.result_signal.emit((host, ports, device_name))
                    except Exception as e:
                        print(f"Erreur lors du scan de {host} : {e}")

                    # Mise à jour de la progression
                    self.progress_signal.emit((index + 1) * 100 // total_hosts)

        except Exception as e:
            print(f"Erreur dans le thread de scan réseau : {e}")
        finally:
            self.progress_signal.emit(100)

    def stop(self):
        """Arrête le thread de scan."""
        self._is_running = False
        self._scanner.stop()
