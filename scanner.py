from scapy.all import sniff, IP, TCP
from collections import Counter
import time

# Threshold for "suspicious" activity (packets per 10 seconds)
THRESHOLD = 50
packet_counts = Counter()
start_time = time.time()

def process_packet(packet):
    global start_time
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1
        
        # Check every 10 seconds
        current_time = time.time()
        if current_time - start_time > 10:
            for ip, count in packet_counts.items():
                if count > THRESHOLD:
                    print(f"[!] ALERT: Potential DoS Attack from {ip} ({count} packets detected)")
            
            # Reset counter for the next window
            packet_counts.clear()
            start_time = current_time

print("IDS is active... monitoring network traffic.")
# Sniff traffic (requires Admin/Sudo privileges)
sniff(filter="ip", prn=process_packet, store=0)