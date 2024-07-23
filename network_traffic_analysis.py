import argparse
import os
import threading
import subprocess
from scapy.all import sniff, wrpcap, rdpcap, PcapWriter
import tkinter as tk
from tkinter import filedialog, ttk
import psutil
import sys
import networkx as nx
import matplotlib.pyplot as plt
import sqlite3
from datetime import datetime
from collections import Counter

# Global variables
capture_thread = None
stop_capture = False
connections = {}
packet_stats = {}

# Initialize the database
def init_db():
    conn = sqlite3.connect('network_traffic.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            proto TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER,
            payload TEXT
        )
    ''')
    conn.commit()
    conn.close()
def save_packet_to_db(packet):
    conn = sqlite3.connect('network_traffic.db')
    cursor = conn.cursor()
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
        else:
            ip_src = "Unknown"
            ip_dst = "Unknown"
        
        if packet.haslayer("TCP"):
            proto = "TCP"
            port_src = packet["TCP"].sport
            port_dst = packet["TCP"].dport
        elif packet.haslayer("UDP"):
            proto = "UDP"
            port_src = packet["UDP"].sport
            port_dst = packet["UDP"].dport
        else:
            proto = "Other"
            port_src = None
            port_dst = None

        payload = ''
        if packet.haslayer("Raw"):
            payload = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in packet["Raw"].load)

        length = len(packet)
        
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, proto, src_port, dst_port, length, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, ip_src, ip_dst, proto, port_src, port_dst, length, payload))
        conn.commit()
    except Exception as e:
        print(f"Error saving packet to DB: {e}")
    finally:
        conn.close()
# Function to get details using Nmap
def get_nmap_details(ip):
    try:
        result = subprocess.run(["nmap", "-sP", "-A", "-T4", ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                return line.split("for")[1].strip()
        return "Unknown"
    except Exception as e:
        return "Unknown"

# Function to create a human-readable description of the packet
def packet_description(packet, include_payload=False):
    try:
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
            src_org = get_nmap_details(ip_src)
            dst_org = get_nmap_details(ip_dst)
        else:
            ip_src = "Unknown"
            ip_dst = "Unknown"
            src_org = "Unknown"
            dst_org = "Unknown"
        
        if packet.haslayer("TCP"):
            proto = "TCP"
            port_src = packet["TCP"].sport
            port_dst = packet["TCP"].dport
        elif packet.haslayer("UDP"):
            proto = "UDP"
            port_src = packet["UDP"].sport
            port_dst = packet["UDP"].dport
        else:
            proto = "Other"
            port_src = "Unknown"
            port_dst = "Unknown"
        
        description = f"{ip_src}:{port_src} ({src_org}) -> {ip_dst}:{port_dst} ({dst_org}) ({proto})"

        if include_payload and packet.haslayer("Raw"):
            payload = packet["Raw"].load
            payload_str = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in payload)
            description += f"\nPayload: {payload_str}\n"
        
        return description
    except Exception as e:
        return f"Error processing packet: {e}"

# Packet callback function
def packet_callback(packet, writer):
    try:
        basic_description = packet_description(packet)
        detailed_description = packet_description(packet, include_payload=True)
        print(basic_description)
        writer.write(packet)
        with open('traffic_analysis.log', 'a') as log_file:
            log_file.write(detailed_description + '\n')
        
        # Save to database
        save_packet_to_db(packet)
        
        # Update packet statistics
        update_packet_stats(packet)
        
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            ip_dst = packet["IP"].dst
            if ip_src not in connections:
                connections[ip_src] = []
            if ip_dst not in connections[ip_src]:
                connections[ip_src].append(ip_dst)
    except Exception as e:
        print(f"Error processing packet: {e}")

# Update packet statistics
def update_packet_stats(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        proto = get_protocol(packet)
        src_port = get_source_port(packet)
        dst_port = get_destination_port(packet)
        
        key = (ip_src, ip_dst, proto, src_port, dst_port)
        if key not in packet_stats:
            packet_stats[key] = {'packets': 0, 'bytes': 0}
        packet_stats[key]['packets'] += 1
        packet_stats[key]['bytes'] += len(packet)

# Get protocol from packet
def get_protocol(packet):
    if packet.haslayer("TCP"):
        return "TCP"
    elif packet.haslayer("UDP"):
        return "UDP"
    else:
        return "Other"

# Get source port from packet
def get_source_port(packet):
    if packet.haslayer("TCP"):
        return packet["TCP"].sport
    elif packet.haslayer("UDP"):
        return packet["UDP"].sport
    else:
        return "Unknown"

# Get destination port from packet
def get_destination_port(packet):
    if packet.haslayer("TCP"):
        return packet["TCP"].dport
    elif packet.haslayer("UDP"):
        return packet["UDP"].dport
    else:
        return "Unknown"

# Capture live traffic
def capture_live(interface, filters, traffic_type, output_file):
    global stop_capture
    print(f"Starting live capture on {interface} with filters '{filters}'...")
    writer = PcapWriter(output_file, append=True, sync=True)
    bpf_filter = " or ".join(filters)
    
    # Add traffic type filter
    if traffic_type == 'inbound':
        bpf_filter = f"{bpf_filter} and dst host {psutil.net_if_addrs()[interface][0].address}"
    elif traffic_type == 'outbound':
        bpf_filter = f"{bpf_filter} and src host {psutil.net_if_addrs()[interface][0].address}"
    
    # Exclude DNS traffic on port 53
    bpf_filter = f"({bpf_filter}) and not port 53"

    sniff(iface=interface, filter=bpf_filter, prn=lambda x: packet_callback(x, writer), store=False, stop_filter=lambda x: stop_capture)

# Read pcap file
def read_pcap(file):
    print(f"Reading packets from {file}...")
    packets = rdpcap(file)
    for packet in packets:
        print(packet_description(packet, include_payload=True))
        update_packet_stats(packet)

# Save packet summary to file (text format)
def save_to_file(filename, data):
    with open(filename, 'w') as file:
        file.write(data)

# Get network interfaces
def get_network_interfaces():
    return psutil.net_if_addrs().keys()

# Function to draw network graph
def draw_network_graph():
    G = nx.DiGraph()  # Directed graph to show the direction of traffic
    for src, dsts in connections.items():
        for dst in dsts:
            G.add_edge(src, dst)
    
    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, node_size=700, node_color="skyblue", font_size=10, font_weight="bold", arrows=True)
    plt.title("Network Connections Graph")
    plt.tight_layout()
    
    # Save the figure before showing it
    plt.savefig('network_graph.png')
    
    # Show the graph in a separate window
    plt.show()

# Function to save graph image
def save_graph_image():
    plt.figure(figsize=(10, 8))
    G = nx.DiGraph()  # Directed graph to show the direction of traffic
    for src, dsts in connections.items():
        for dst in dsts:
            G.add_edge(src, dst)
    
    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, node_size=700, node_color="skyblue", font_size=10, font_weight="bold", arrows=True)
    plt.title("Network Connections Graph")
    plt.tight_layout()
    
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
    if file_path:
        plt.savefig(file_path)
        print(f"Graph image saved as {file_path}")
    plt.close()

# Function to display packet statistics
def display_packet_stats():
    top_hosts = sorted([(k[0], v['packets']) for k, v in packet_stats.items()], key=lambda x: x[1], reverse=True)[:10]
    top_destinations = sorted([(k[1], v['packets']) for k, v in packet_stats.items()], key=lambda x: x[1], reverse=True)[:10]
    top_protocols = sorted([(k[2], v['packets']) for k, v in packet_stats.items()], key=lambda x: x[1], reverse=True)[:5]
    top_ports = sorted([(f"{k[3]}->{k[4]}", v['packets']) for k, v in packet_stats.items()], key=lambda x: x[1], reverse=True)[:10]

    print("Top 10 Hosts by Packets:")
    for host, packets in top_hosts:
        print(f"{host}: {packets} packets")

    print("\nTop 10 Destinations by Packets:")
    for dst, packets in top_destinations:
        print(f"{dst}: {packets} packets")

    print("\nTop 5 Protocols by Packets:")
    for proto, packets in top_protocols:
        print(f"{proto}: {packets} packets")

    print("\nTop 10 Ports by Packets:")
    for port, packets in top_ports:
        print(f"{port}: {packets} packets")

# Main function for CLI
def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analysis Tool")
    subparsers = parser.add_
# Main function for CLI
def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analysis Tool")
    subparsers = parser.add_subparsers(dest="command")

    live_parser = subparsers.add_parser("live", help="Capture live network traffic")
    live_parser.add_argument("-i", "--interface", required=True, help="Network interface to capture traffic on")
    live_parser.add_argument("-f", "--filter", nargs='+', default=[], help="BPF filters for packet capture")
    live_parser.add_argument("-t", "--type", choices=['all', 'inbound', 'outbound'], default='all', help="Type of traffic to capture")
    live_parser.add_argument("-o", "--output", required=True, help="Output pcap file to save packets")

    pcap_parser = subparsers.add_parser("pcap", help="Read packets from pcap file")
    pcap_parser.add_argument("-r", "--read", required=True, help="Path to pcap file")

    save_parser = subparsers.add_parser("save", help="Save packet summary to file")
    save_parser.add_argument("-o", "--output", required=True, help="Output file to save packet summaries")

    stats_parser = subparsers.add_parser("stats", help="Display packet statistics")

    args = parser.parse_args()

    if args.command == "live":
        capture_live(args.interface, args.filter, args.type, args.output)
    elif args.command == "pcap":
        read_pcap(args.read)
    elif args.command == "save":
        if os.path.exists('traffic_analysis.log'):
            with open('traffic_analysis.log', 'r') as file:
                data = file.read()
            save_to_file(args.output, data)
        else:
            print("Log file 'traffic_analysis.log' does not exist.")
    elif args.command == "stats":
        display_packet_stats()
    else:
        parser.print_help()

# GUI Implementation
def start_gui():
    def start_live_capture():
        global capture_thread, stop_capture
        interface = interface_combobox.get()
        selected_filters = [var.get() for var in filter_vars if var.get()]
        traffic_type = traffic_type_var.get()
        output_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if output_file:
            stop_capture = False
            capture_thread = threading.Thread(target=capture_live, args=(interface, selected_filters, traffic_type, output_file))
            capture_thread.start()

    def stop_live_capture():
        global stop_capture
        stop_capture = True
        if capture_thread:
            capture_thread.join()
        print("Live capture stopped.")
        print(display_packet_stats())

    def open_pcap_file():
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            read_pcap(file_path)

    def save_log_file():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            if os.path.exists('traffic_analysis.log'):
                with open('traffic_analysis.log', 'r') as file:
                    data = file.read()
                save_to_file(file_path, data)
            else:
                with open('traffic_analysis.log', 'w') as file:
                    file.write("No data captured yet.")
                print("Log file 'traffic_analysis.log' did not exist. It has been created with a placeholder message.")

    def show_network_graph():
        draw_network_graph()

    def save_graph_image():
        save_graph_image()

    root = tk.Tk()
    root.title("Network Traffic Analysis Tool")

    tk.Label(root, text="Network Interface:").grid(row=0, column=0)
    interface_combobox = ttk.Combobox(root, values=list(get_network_interfaces()))
    interface_combobox.grid(row=0, column=1)

    tk.Label(root, text="BPF Filters:").grid(row=1, column=0)
    filter_frame = tk.Frame(root)
    filter_frame.grid(row=1, column=1)
    filters = {
        "tcp": "tcp", "udp": "udp", "http": "port 80", "https": "port 443",
        "ftp": "port 21", "smtp": "port 25", "pop3": "port 110", "imap": "port 143"
    }
    filter_vars = []
    for filter_name, filter_value in filters.items():
        var = tk.StringVar(value="")
        filter_vars.append(var)
        cb = tk.Checkbutton(filter_frame, text=filter_name, variable=var, onvalue=filter_value, offvalue="")
        cb.pack(anchor='w')

    tk.Label(root, text="Traffic Type:").grid(row=2, column=0)
    traffic_type_var = tk.StringVar(value="all")
    traffic_type_frame = tk.Frame(root)
    traffic_type_frame.grid(row=2, column=1)
    traffic_types = [("All", "all"), ("Inbound", "inbound"), ("Outbound", "outbound")]
    for text, mode in traffic_types:
        rb = tk.Radiobutton(traffic_type_frame, text=text, variable=traffic_type_var, value=mode)
        rb.pack(anchor='w')

    tk.Button(root, text="Start Live Capture", command=start_live_capture).grid(row=3, column=0)
    tk.Button(root, text="Stop Capture", command=stop_live_capture).grid(row=3, column=1)
    tk.Button(root, text="Open PCAP File", command=open_pcap_file).grid(row=4, column=0)
    tk.Button(root, text="Save Logs", command=save_log_file).grid(row=4, column=1)
    tk.Button(root, text="Show Network Graph", command=show_network_graph).grid(row=5, column=0)
    tk.Button(root, text="Save Graph Image", command=save_graph_image).grid(row=5, column=1)

    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        init_db()
        start_gui()
    else:
        main()
    
