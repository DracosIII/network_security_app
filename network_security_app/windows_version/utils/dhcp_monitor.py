from scapy.all import sniff, DHCP

def monitor_dhcp():
    """Surveille les paquets DHCP pour identifier les destinations."""
    def process_packet(packet):
        if packet.haslayer(DHCP):
            options = packet[DHCP].options
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == "requested_addr":
                    print(f"Adresse IP demandée : {opt[1]}")

    sniff(filter="udp and (port 67 or port 68)", prn=process_packet, store=0)
