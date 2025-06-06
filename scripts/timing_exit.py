#!/usr/bin/env python3
import csv
import time
import socket
import pickle
import threading
from scapy.all import *

# Configuration
EXIT_ADDR = "10.0.10.2"
LISTEN_PORT = 9999

# Array to store all received packets
entry_packets = []
exit_packets = []
packet_lock = threading.Lock()

def packet_handler(packet):
    """Handle captured packets"""
    if IP in packet and packet[IP].src == EXIT_ADDR and len(packet) == 602: # Standard tor packet size 512B

        # Check for TCP and Raw layers (likely to contain HTTP)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            service = None

            if 'HTTP' in payload:
                match = re.search(r'^Host:\s*(.+)', payload, re.MULTILINE)
                if match:
                    service = match.group(1).strip()

            with packet_lock:   
                packet_info = {
                    'src': packet[IP].src,
                    'dst': packet[IP].dst,
                    'time': time.time(),
                    'size': len(packet),
                    'service': service,
                    #'payload': payload,
                }
                exit_packets.append(packet_info)

def receive_packets():
    """Listen for incoming packet data"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((EXIT_ADDR, LISTEN_PORT))
    
    print(f"Listening for packets on {EXIT_ADDR}:{LISTEN_PORT}")
    
    while True:
        try:
            data, addr = sock.recvfrom(65535)  # Max UDP packet size
            packets = pickle.loads(data)
            
            with packet_lock:
                entry_packets.extend(packets)
                print(f"Received {len(packets)} packets from {addr[0]}. Total stored: {len(entry_packets)}")
                
        except Exception as e:
            print(f"Error receiving packets: {e}")

def print_stats():
    """Print statistics every 10 seconds"""
    import time
    while True:
        time.sleep(10)
        with packet_lock:
            if entry_packets:
                print(f"\n--- Statistics ---")
                print(f"Total packets stored: {len(entry_packets)}")
                print(f"Latest packet: {entry_packets[-1]}")
                print("-----------------\n")

def save_to_csv(filename, data):
    """Save packet data to a CSV file"""
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

if __name__ == "__main__":
    print(f"Starting packet receiver on {EXIT_ADDR}:{LISTEN_PORT}")
    
    # Start receiver thread
    receiver_thread = threading.Thread(target=receive_packets, daemon=True)
    receiver_thread.start()
    
    # Start stats thread
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()

    # Start packet capture
    sniff(filter=f"src host {EXIT_ADDR}", prn=packet_handler, store=0)
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        with packet_lock:
            save_to_csv('entry_packets.csv', entry_packets)
            save_to_csv('exit_packets.csv', exit_packets)
            print(f"Final count: {len(entry_packets)} packets stored")
