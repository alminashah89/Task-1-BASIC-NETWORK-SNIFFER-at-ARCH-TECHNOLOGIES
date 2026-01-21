import threading
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, conf
import tkinter as tk
from tkinter import ttk
import datetime

LOG_FILE = "packet_logs.txt"

# Force L3 sniffing on Windows to avoid Layer 2 issues
conf.L2socket = conf.L3socket

# GUI packet table reference
table = None
root = None

def log_packet(text):
    """Write packet info to log file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(text + "\n")
    except Exception as e:
        print("Logging error:", e)

def safe_insert(values):
    """Insert into GUI table safely from threads."""
    if root:
        root.after(0, lambda: table.insert("", "end", values=values))

def analyze_packet(packet):
    """Analyze each captured packet and update GUI + logs."""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"

        proto = "OTHER"
        details = ""

        if packet.haslayer(TCP):
            proto = "TCP"
            details = f"SRC Port={packet[TCP].sport}, DST Port={packet[TCP].dport}"
        elif packet.haslayer(UDP):
            proto = "UDP"
            details = f"SRC Port={packet[UDP].sport}, DST Port={packet[UDP].dport}"
        elif packet.haslayer(ARP):
            proto = "ARP"
            details = "Address Resolution Protocol"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            details = f"Type={packet[ICMP].type}"

        row = (timestamp, src_ip, dst_ip, proto, details)

        # Update GUI safely
        safe_insert(row)

        # Log packet
        log_packet(f"{timestamp} | {src_ip} -> {dst_ip} | {proto} | {details}")

    except Exception as e:
        print("Error processing packet:", e)

# Sniff control
sniffing = False

def sniffer_thread():
    """Background thread for capturing packets."""
    sniff(prn=analyze_packet, store=False, stop_filter=lambda p: not sniffing, filter="ip")

def start_sniffing():
    """Start sniffing in a background thread."""
    global sniffing
    sniffing = True
    threading.Thread(target=sniffer_thread, daemon=True).start()

def stop_sniffing():
    """Stop sniffing."""
    global sniffing
    sniffing = False

# GUI setup
root = tk.Tk()
root.title("Network Sniffer - Windows Compatible")
root.geometry("900x500")
root.configure(bg="black")

title_label = tk.Label(root, text="Network Packet Sniffer", font=("Arial", 16, "bold"),
                       bg="black", fg="cyan")
title_label.pack(pady=10)

columns = ("Time", "IP Source", "IP Dest", "Protocol", "Details")
table = ttk.Treeview(root, columns=columns, show="headings", height=20)
table.pack(fill=tk.BOTH, expand=True)

for col in columns:
    table.heading(col, text=col)
    table.column(col, width=150)

button_frame = tk.Frame(root, bg="black")
button_frame.pack(pady=10)

start_btn = tk.Button(button_frame, text="Start Sniffing", font=("Arial", 12),
                      bg="green", fg="white", width=15, command=start_sniffing)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(button_frame, text="Stop Sniffing", font=("Arial", 12),
                     bg="red", fg="white", width=15, command=stop_sniffing)
stop_btn.grid(row=0, column=1, padx=10)

root.mainloop()
