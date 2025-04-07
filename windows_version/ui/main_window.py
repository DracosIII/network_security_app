from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget, 
                            QTextEdit, QPushButton, QProgressBar, QLabel)
from PyQt6.QtCore import Qt
from core.scanner_thread import NetworkScanThread

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Security Tool")
        self.setMinimumSize(800, 600)
        self.scan_thread = None
        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.tabs = QTabWidget()
        
        # Scan Tab
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        
        self.progress = QProgressBar()
        
        scan_layout.addWidget(self.scan_output)
        scan_layout.addWidget(self.scan_btn)
        scan_layout.addWidget(self.stop_btn)
        scan_layout.addWidget(self.progress)
        
        self.tabs.addTab(scan_tab, "Network Scan")
        layout.addWidget(self.tabs)

    def start_scan(self):
        self.scan_output.clear()
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setValue(0)
        
        self.scan_thread = NetworkScanThread("192.168.1")
        self.scan_thread.result_signal.connect(self.update_results)
        self.scan_thread.progress_signal.connect(self.progress.setValue)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    def update_results(self, result):
        host, ports = result
        self.scan_output.append(f"{host}: {ports}")

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread.wait()

    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.scan_thread = None