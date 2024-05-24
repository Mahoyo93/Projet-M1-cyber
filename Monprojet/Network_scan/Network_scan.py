import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import scapy.all as scapy


class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.geometry("400x400")
        
        self.create_widgets()

    def create_widgets(self):
        self.label_target = tk.Label(self, text="Target IP or IP Range:")
        self.label_target.pack(pady=5)
        
        self.entry_target = tk.Entry(self, width=30)
        self.entry_target.pack()

        self.scan_button = tk.Button(self, text="Scan", command=self.scan_network)
        self.scan_button.pack(pady=10)

        self.result_text = ScrolledText(self, width=40, height=15)
        self.result_text.pack(pady=10)

    def scan_network(self):
        target_ip = self.entry_target.get()
        if not target_ip:
            messagebox.showwarning("Warning", "Please enter a target IP or IP range.")
            return
        
        scan_result = self.scan(target_ip)
        self.display_result(scan_result)

    def scan(self, ip: str):
        """Scans the network for IP and MAC address pairs."""
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        client_list = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
        return client_list

    def display_result(self, result_list):
        """Displays the scan result in the text area."""
        self.result_text.delete(1.0, tk.END)  # Clear previous result
        self.result_text.insert(tk.END, "IP\t\t\tMAC\n----------------------------------------\n")
        for client in result_list:
            self.result_text.insert(tk.END, f"{client['ip']}\t\t{client['mac']}\n")


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()
