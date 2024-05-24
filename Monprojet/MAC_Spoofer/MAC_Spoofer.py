import subprocess
import tkinter as tk
from tkinter import messagebox

class MacChangerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MAC Spoofer")
        self.geometry("400x200")
        self.create_widgets()

    def create_widgets(self):
        self.label_interface = tk.Label(self, text="Interface:")
        self.label_interface.pack(pady=5)
        
        self.entry_interface = tk.Entry(self, width=30)
        self.entry_interface.pack()

        self.label_mac = tk.Label(self, text="New MAC Address:")
        self.label_mac.pack(pady=5)
        
        self.entry_mac = tk.Entry(self, width=30)
        self.entry_mac.pack()

        self.change_button = tk.Button(self, text="Change MAC", command=self.change_mac)
        self.change_button.pack(pady=10)

    def change_mac(self):
        interface = self.entry_interface.get()
        new_mac = self.entry_mac.get()

        if not interface or not new_mac:
            messagebox.showwarning("Warning", "Please enter both interface and new MAC address.")
            return

        try:
            subprocess.call(["ifconfig", interface, "down"])
            subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
            subprocess.call(["ifconfig", interface, "up"])
            messagebox.showinfo("Success", f"MAC address for {interface} changed to {new_mac}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    app = MacChangerApp()
    app.mainloop()
