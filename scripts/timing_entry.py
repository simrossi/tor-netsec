#!/usr/bin/env python3
import time
import socket
import pickle
import threading
from scapy.all import *

# Configuration
ENTRY_ADDR = "192.168.2.1"
EXIT_ADDR = "192.168.2.4"
EXIT_PORT = 9999

# Global array to store captured packets
captured_packets = []
packet_lock = threading.Lock()

def packet_handler(packet):
    """Handle captured packets"""
    if IP in packet and packet[IP].dst == ENTRY_ADDR and len(packet) == 602: # Standard tor packet size 512B
        with packet_lock:
            packet_info = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'time': time.time(),
                'size': len(packet)
            }

            captured_packets.append(packet_info)

def send_packets():
    """Send captured packets every second"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    while True:
        time.sleep(1)
        
        with packet_lock:
            if captured_packets:
                # Send the array
                try:
                    data = pickle.dumps(captured_packets)
                    sock.sendto(data, (EXIT_ADDR, EXIT_PORT))
                    print(f"Sent {len(captured_packets)} packets to {EXIT_ADDR}")
                    # Clear the sent packets
                    captured_packets.clear()
                except Exception as e:
                    print(f"Error sending packets: {e}")

if __name__ == "__main__":
    print(f"Starting packet capture on {ENTRY_ADDR}")
    print(f"Will send captured packets to {EXIT_ADDR}:{EXIT_PORT}")
    
    # Start the sender thread
    sender_thread = threading.Thread(target=send_packets, daemon=True)
    sender_thread.start()
    
    # Start packet capture
    sniff(filter=f"dst host {ENTRY_ADDR}", prn=packet_handler, store=0)
