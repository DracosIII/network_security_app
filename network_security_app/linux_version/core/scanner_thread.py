from PyQt6.QtCore import QThread, pyqtSignal
from core.network_scanner import NetworkScanner
import concurrent.futures

class NetworkScanThread(QThread):
    result_signal = pyqtSignal(tuple)  # (host, ports)
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
                        print(f"Hôte détecté : {host}, Ports ouverts : {ports}")  # Log pour déboguer
                        self.result_signal.emit((host, ports))
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
