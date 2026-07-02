import customtkinter as ctk
from tkinter import messagebox, ttk
import threading
import time
import socket
import subprocess
import re
from scapy.all import sr1, IP, ICMP
from datetime import datetime
import os
import webbrowser

# Configurazione Tema Scuro
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class AuraScan(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AuraScan - Network Intelligence")
        self.geometry("1000x700")
        
        # Variabili di stato
        self.scanning = False
        self.results_data = []
        
        # Layout Grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR (Controlli) ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(self.sidebar, text="AURA SCAN", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        credit = ctk.CTkLabel(self.sidebar, text="Credits: gabrieleviola.it", text_color="#3b82f6", cursor="hand2")
        credit.pack(pady=(0, 10))
        credit.bind("<Button-1>", lambda _event: webbrowser.open("https://gabrieleviola.it/"))

        # Sezioni di Scansione
        self.section_title = ctk.CTkLabel(self.sidebar, text="Modalità Scan", font=("Segoe UI", 14, "bold"))
        self.section_title.pack(pady=(10, 5))

        btn_style = {"width": 200, "height": 45}
        
        self.btn_quick = ctk.CTkButton(self.sidebar, text="🚀 Scan Veloce (IP Locali)", 
                                       command=lambda: self.start_scan("quick"), **btn_style)
        self.btn_quick.pack(pady=10)

        self.btn_deep = ctk.CTkButton(self.sidebar, text="🛡️ Audit Sicurezza Profondo", 
                                      command=lambda: self.start_scan("deep"), **btn_style)
        self.btn_deep.pack(pady=10)

        self.btn_printers = ctk.CTkButton(self.sidebar, text="🖨️ Cerca Stampanti", 
                                          command=lambda: self.start_scan("printers"), **btn_style)
        self.btn_printers.pack(pady=10)

        # Area Log
        log_frame = ctk.CTkFrame(self.sidebar, fg_color="#2b2b2b")
        log_frame.pack(fill="x", padx=20, pady=30)
        
        ctk.CTkLabel(log_frame, text="Log Operativo", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.log_text = ctk.CTkTextbox(log_frame, height=250, state="disabled")
        self.log_text.pack(fill="x", padx=10, pady=(10, 10))

        # --- MAIN AREA (Risultati) ---
        self.main_area = ctk.CTkFrame(self, fg_color="#1e1e1e")
        self.main_area.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

        # Header Risultati
        header_frame = ctk.CTkFrame(self.main_area, height=50)
        header_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        self.lbl_status = ctk.CTkLabel(header_frame, text="Pronto", font=("Segoe UI", 16), text_color="#4ade80")
        self.lbl_status.pack(side="left", padx=20)

        # Tabella Risultati (Treeview customizzato)
        tree_frame = ctk.CTkFrame(self.main_area)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        columns = ("IP", "Host", "Porte Aperte", "Servizi Rilevati", "Stato")
        
        # Creazione Tabella
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        self.tree.tag_configure("high", foreground="#ef4444")
        self.tree.tag_configure("medium", foreground="#facc15")
        self.tree.tag_configure("normal", foreground="#4ade80")
        self.tree.tag_configure("offline", foreground="#9ca3af")
        
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "IP":
                self.tree.column(col, width=150)
            elif col == "Stato":
                self.tree.column(col, width=80)
            else:
                self.tree.column(col, width=200)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def log(self, message):
        """Aggiorna il log sidebar"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def start_scan(self, mode):
        if self.scanning:
            messagebox.showinfo("Info", "Scansione in corso... attendi.")
            return
        
        self.scanning = True
        self.lbl_status.configure(text="In Scansione...", text_color="#facc15")
        self.btn_quick.configure(state="disabled")
        self.btn_deep.configure(state="disabled")
        self.btn_printers.configure(state="disabled")

        # Thread separato per non bloccare la GUI
        thread = threading.Thread(target=self._run_scan_logic, args=(mode,), daemon=True)
        thread.start()

    def _run_scan_logic(self, mode):
        """Logica di scansione vera e propria"""
        
        # 1. Rileva IP locale per capire la rete (es. 192.168.1.x)
        local_ip = self._get_local_ip()
        base_ip = ".".join(local_ip.split(".")[:3])
        self.log(f"Rete rilevata: {base_ip}.0/24")

        # Lista target da scansionare
        targets = []
        
        if mode == "quick":
            targets = [f"{base_ip}.{i}" for i in range(1, 30)] # Solo primi 30 IP per velocità
            self.log("Avviata Scan Veloce (Primi 30 host)...")
            
        elif mode == "deep":
            targets = [f"{base_ip}.{i}" for i in range(1, 254)] # Tutta la rete
            self.log("Avviata Audit Profondo (Tutta la rete)...")

        elif mode == "printers":
            # Cerca solo porte comuni stampanti (9100, 515)
            targets = [f"{base_ip}.{i}" for i in range(1, 254)]
            self.log("Ricerca Stampanti di rete...")

        # Scansione Loop
        for target in targets:
            if not self.scanning: break
            
            status = "Offline"
            ports = []
            services = []
            
            # Ping veloce (ICMP)
            try:
                response = sr1(IP(dst=target)/ICMP(), timeout=0.5, verbose=False)
                if response:
                    status = "Online"
                    
                    # Se è una scan profonda o stampanti, controlliamo le porte
                    if mode in ["deep", "printers"]:
                        ports, services = self._check_ports(target, include_printers=(mode == "printers"))
                        
                        # Logica specifica per Stampanti
                        if mode == "printers":
                            if 9100 in ports or 515 in ports:
                                status += " (STAMPANTE)"
            except Exception as e:
                pass

            # Aggiorna UI (dalla thread worker)
            self.after(0, lambda t=target, s=status, p=ports, sv=services: 
                       self._update_tree(t, s, p, sv))

        # Fine Scansione
        self.scanning = False
        self.lbl_status.configure(text="Scan Completata", text_color="#4ade80")
        self.btn_quick.configure(state="normal")
        self.btn_deep.configure(state="normal")
        self.btn_printers.configure(state="normal")
        self.log("Scansione terminata.")

    def _check_ports(self, ip, include_printers=False):
        """Controlla porte critiche e servizi"""
        open_ports = []
        services_found = []
        
        # Porte comuni da controllare (Sicurezza)
        critical_ports = [21, 22, 23, 80, 443, 445, 3389, 8080]
        if include_printers:
            critical_ports.extend([515, 631, 9100])
        
        for port in critical_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3) # Molto veloce
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                open_ports.append(port)
                
                # Identificazione servizi (Semplice)
                service_map = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
                               443: "HTTPS", 445: "SMB", 515: "LPD", 631: "IPP",
                               3389: "RDP", 8080: "HTTP-ALT", 9100: "JetDirect"}
                
                if port in service_map:
                    services_found.append(f"{service_map[port]}")
            
            sock.close()

        # Rilevamento OS (Fingerprinting TTL)
        try:
            response = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=False)
            if response and IP in response:
                ttl = response[IP].ttl
                os_guess = "Windows" if 128 <= ttl <= 130 else "Linux/Unix" if 64 <= ttl < 128 else "Sconosciuto"
                services_found.append(f"OS: {os_guess}")
        except: pass

        return open_ports, services_found

    def _update_tree(self, ip, status, ports, services):
        """Aggiorna la tabella in sicurezza"""
        # Formatta porte per lettura facile
        port_str = ", ".join(map(str, ports)) if ports else "-"
        
        # Logica colore stato
        color = "normal"
        if status == "Offline":
            color = "offline"
        elif any(p in [21, 23] for p in ports):
            color = "high"
        elif any(p in [80, 445, 3389, 8080, 9100] for p in ports):
            color = "medium"
            
        self.tree.insert("", "end", values=(ip, status, port_str, ", ".join(services), status), tags=(color,))

    def _get_local_ip(self):
        """Trova l'IP locale della macchina"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

if __name__ == "__main__":
    app = AuraScan()
    app.mainloop()
