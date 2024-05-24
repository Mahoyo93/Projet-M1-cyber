import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("400x400")
        
        self.create_widgets()

    def create_widgets(self):
        self.label_host = tk.Label(self, text="Target Host:")
        self.label_host.pack(pady=5)
        
        self.entry_host = tk.Entry(self, width=30)
        self.entry_host.pack()

        self.label_ports = tk.Label(self, text="Port Range (e.g., 1-1000):")
        self.label_ports.pack(pady=5)
        
        self.entry_ports = tk.Entry(self, width=30)
        self.entry_ports.pack()

        self.syn_var = tk.BooleanVar()
        self.check_syn = tk.Checkbutton(self, text="SYN Scan (-sS)", variable=self.syn_var)
        self.check_syn.pack(pady=5)

        self.version_var = tk.BooleanVar()
        self.check_version = tk.Checkbutton(self, text="Version Detection (-sV)", variable=self.version_var)
        self.check_version.pack()

        self.scan_button = tk.Button(self, text="Scan", command=self.scan_ports)
        self.scan_button.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self, width=40, height=15, state=tk.DISABLED)
        self.result_text.pack(pady=10)

    def port_scan(self, host, port, result_list):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, int(port)))
                result_list.append(f"{host} tcp/{port} open")

        except (socket.timeout, ConnectionRefusedError):
            result_list.append(f"{host} tcp/{port} closed")

    def scan_ports(self):
        host = self.entry_host.get()
        ports_range = self.entry_ports.get()
        syn_scan = self.syn_var.get()
        version_detection = self.version_var.get()
        
        if not host or not ports_range:
            messagebox.showwarning("Warning", "Please enter both target host and port range.")
            return
        
        result_list = []
        host_ip = socket.gethostbyname(host)
        
        # Gérer la plage de ports
        try:
            ports_start, ports_end = map(int, ports_range.split("-"))
        except ValueError:
            messagebox.showwarning("Warning", "Invalid port range format. Please use 'start-end' format.")
            return

        # Lancer des threads pour scanner les ports
        threads = []
        for port in range(ports_start, ports_end + 1):
            t = threading.Thread(target=self.port_scan, args=(host_ip, port, result_list))
            threads.append(t)
            t.start()
        
        # Attendre la fin de tous les threads
        for t in threads:
            t.join()
        
        # Afficher les résultats dans la zone de texte
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        for result in result_list:
            self.result_text.insert(tk.END, result + "\n")
        self.result_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
