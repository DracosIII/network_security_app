from PyQt6.QtCore import QThread, pyqtSignal
from core.network_scanner import NetworkScanner

class NetworkScanThread(QThread):
    result_signal = pyqtSignal(tuple)
    progress_signal = pyqtSignal(int)

    def __init__(self, network_prefix):
        super().__init__()
        self.network_prefix = network_prefix
        self.scanner = NetworkScanner()
        self._running = True

    def run(self):
        hosts = self.scanner.discover_hosts(self.network_prefix)
        for i, host in enumerate(hosts):
            if not self._running:
                break
            ports = self.scanner.scan_ports(host, [21, 22, 80, 443])
            self.result_signal.emit((host, ports))
            self.progress_signal.emit(int((i+1)/len(hosts)*100))

    def stop(self):
        self._running = False