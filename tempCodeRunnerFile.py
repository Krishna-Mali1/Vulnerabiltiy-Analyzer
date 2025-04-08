import tkinter as tk
from tkinter import ttk, scrolledtext
from vulnerability.sql import SQL
from vulnerability.xss import XSS
from vulnerability.authentication import Authentication
import threading
import requests


class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Scanner")

        # Set window dimensions
        window_width = 600
        window_height = 580

        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        position_x = (screen_width - window_width) // 2
        position_y = (screen_height - window_height) // 2

        self.root.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        main_frame = tk.Frame(root)
        main_frame.pack(pady=10)

        # Input Fields
        tk.Label(main_frame, text="Target URL:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.url_entry = tk.Entry(main_frame, width=60)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(main_frame, text="Login URL:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.login_url_entry = tk.Entry(main_frame, width=60)
        self.login_url_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(main_frame, text="Username:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = tk.Entry(main_frame, width=60)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(main_frame, text="Password:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = tk.Entry(main_frame, width=60, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(main_frame, text="URLs to Ignore:").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.ignore_entry = tk.Entry(main_frame, width=60)
        self.ignore_entry.grid(row=4, column=1, padx=5, pady=5)

        # Attack type radio buttons
        tk.Label(main_frame, text="Select Attack Type:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        attack_frame = tk.Frame(main_frame)
        attack_frame.grid(row=5, column=1, padx=5, pady=5)

        self.attack_type = tk.StringVar(value="all")
        tk.Radiobutton(attack_frame, text="SQL Injection", variable=self.attack_type, value="sql").pack(side="left", padx=5)
        tk.Radiobutton(attack_frame, text="XSS", variable=self.attack_type, value="xss").pack(side="left", padx=5)
        tk.Radiobutton(attack_frame, text="Authentication", variable=self.attack_type, value="auth").pack(side="left", padx=5)
        tk.Radiobutton(attack_frame, text="All", variable=self.attack_type, value="all").pack(side="left", padx=5)

        # Buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        self.scan_button = tk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side="left", padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side="left", padx=10)

        # Progress bar
        self.progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="indeterminate")
        self.progress.pack(pady=10)

        # Output display
        self.output_text = scrolledtext.ScrolledText(root, width=70, height=15)
        self.output_text.pack(padx=10, pady=10)

        # Creator info
        self.creator_label = tk.Label(root, text="Vulnerability Scanner created by Krishna Mali, Malhar Acharya, Darshil Chocha", font=("Arial", 10, "italic"))
        self.creator_label.pack(pady=5)

        self.scan_thread = None
        self.stop_flag = threading.Event()

    def stop_scan(self):
        self.stop_flag.set()
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output_text.insert(tk.END, "\n[+] Scan Stopped by User.\n")

    def start_scan(self):
        self.output_text.delete("1.0", tk.END)
        self.progress.start()
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        target_url = self.url_entry.get().strip()
        login_url = self.login_url_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        ignore_text = self.ignore_entry.get().strip()
        links_to_ignore = ignore_text.split(',') if ignore_text else []

        if not target_url:
            self.output_text.insert(tk.END, "[!] Target URL is required.\n")
            self.progress.stop()
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return

        # Auth test
        if self.attack_type.get() in ["auth", "all"]:
            if login_url and username and password:
                auth_checker = Authentication(login_url, username, password)
                auth_checker.run_program()
            else:
                self.output_text.insert(tk.END, "[!] Authentication testing requires Login URL, Username, and Password.\n")

        data_dict = {"username": username, "password": password, "Login": "submit"}

        # SQL Injection
        if self.attack_type.get() in ["sql", "all"]:
            scanner = SQL(target_url, links_to_ignore, self.output_text)
            if login_url and username and password:
                scanner.session.post(login_url, data=data_dict)
            scanner.crawl()
            self.output_text.insert(tk.END, "[+] Running SQL Injection Tests...\n")
            scanner.run_program()
            self.output_text.insert(tk.END, "[+] SQL Scan Completed.\n")

        # XSS
        if self.attack_type.get() in ["xss", "all"]:
            scanner = XSS(target_url, links_to_ignore, self.output_text)
            if login_url and username and password:
                scanner.session.post(login_url, data=data_dict)
            scanner.crawl()
            self.output_text.insert(tk.END, "[+] Running XSS Tests...\n")
            scanner.run_program()
            self.output_text.insert(tk.END, "[+] XSS Scan Completed.\n")

        if not self.stop_flag.is_set():
            self.progress.stop()
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.output_text.insert(tk.END, "[+] Scan Finished.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()
