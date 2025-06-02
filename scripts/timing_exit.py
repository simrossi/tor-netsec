#!/usr/bin/env python3
import time
import socket
import pickle
import threading

# Configuration
EXIT_ADDR = "192.168.2.4"
LISTEN_PORT = 9999

# Array to store all received packets
all_packets = []
packets_lock = threading.Lock()

def receive_packets():
    """Listen for incoming packet data"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((EXIT_ADDR, LISTEN_PORT))
    
    print(f"Listening for packets on {EXIT_ADDR}:{LISTEN_PORT}")
    
    while True:
        try:
            data, addr = sock.recvfrom(65535)  # Max UDP packet size
            packets = pickle.loads(data)
            
            with packets_lock:
                all_packets.extend(packets)
                print(f"Received {len(packets)} packets from {addr[0]}. Total stored: {len(all_packets)}")
                
        except Exception as e:
            print(f"Error receiving packets: {e}")

def print_stats():
    """Print statistics every 10 seconds"""
    import time
    while True:
        time.sleep(10)
        with packets_lock:
            if all_packets:
                print(f"\n--- Statistics ---")
                print(f"Total packets stored: {len(all_packets)}")
                print(f"Latest packet: {all_packets[-1]}")
                print("-----------------\n")

if __name__ == "__main__":
    print(f"Starting packet receiver on {EXIT_ADDR}:{LISTEN_PORT}")
    
    # Start receiver thread
    receiver_thread = threading.Thread(target=receive_packets, daemon=True)
    receiver_thread.start()
    
    # Start stats thread
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        with packets_lock:
            print(f"Final count: {len(all_packets)} packets stored")
