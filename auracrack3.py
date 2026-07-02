import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import time
import hashlib
import itertools
import string
import queue
import json
from datetime import datetime
import os
import webbrowser

# Importazione Scapy (richiede privilegi admin su Windows/Mac)
try:
    from scapy.all import sniff, ARP, Ether, srp, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy non installato. Esegui: pip install scapy")
    print("La cattura pacchetti sarà simulata.")

class AuraCrack(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configurazione Finestra
        self.title("AuraCrack - Next Gen Sniffer")
        self.geometry("1000x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Variabili di stato
        self.is_sniffing = False
        self.is_cracking = False
        self.sniff_thread = None
        self.crack_thread = None
        self.log_queue = queue.Queue()
        self.captured_packets = []
        
        # Dizionario password comune
        self.common_passwords = [
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "shadow", "123123", "654321", "superman",
            "qazwsx", "michael", "football", "admin", "root",
            "toor", "guest", "default", "changeme", "password123"
        ]

        # Layout Grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header
        self.create_header()
        
        # Pannello Controlli (Sinistra)
        self.create_control_panel()
        
        # Area Log (Centro)
        self.create_log_area()
        
        # Pannello Destro (Statistiche e Dettagli)
        self.create_stats_panel()
        
        # Avvia il processore di log
        self.process_log_queue()
        
        # Bind per chiusura finestra
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_header(self):
        """Crea l'header dell'applicazione"""
        header = ctk.CTkFrame(self, height=80, corner_radius=0, fg_color="#1a1a1a")
        header.grid(row=0, column=0, columnspan=3, sticky="ew", padx=20, pady=(20, 10))
        
        # Titolo
        lbl_title = ctk.CTkLabel(
            header, 
            text="🔓 AuraCrack Pro v1.0", 
            font=("Arial", 28, "bold"), 
            text_color="#00ff88"
        )
        lbl_title.pack(side="left", padx=20)

        credit = ctk.CTkLabel(header, text="Credits: gabrieleviola.it", text_color="#00ccff", cursor="hand2")
        credit.pack(side="left", padx=8)
        credit.bind("<Button-1>", lambda _event: webbrowser.open("https://gabrieleviola.it/"))
        
        # Status indicator
        self.status_frame = ctk.CTkFrame(header, fg_color="transparent")
        self.status_frame.pack(side="right", padx=20)
        
        self.status_dot = ctk.CTkLabel(
            self.status_frame, 
            text="●", 
            font=("Arial", 20), 
            text_color="red"
        )
        self.status_dot.pack(side="left", padx=5)
        
        self.lbl_status = ctk.CTkLabel(
            self.status_frame, 
            text="Inattivo", 
            font=("Arial", 14)
        )
        self.lbl_status.pack(side="left")

    def create_control_panel(self):
        """Crea il pannello di controllo sinistro"""
        controls = ctk.CTkFrame(self, width=280, fg_color="#2b2b2b")
        controls.grid(row=1, column=0, sticky="ns", padx=(20, 10), pady=10)
        controls.grid_propagate(False)
        
        # Sezione Sniffing
        sniff_frame = ctk.CTkFrame(controls, fg_color="#333333")
        sniff_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            sniff_frame, 
            text="📡 Network Sniffer", 
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        
        self.btn_sniff = ctk.CTkButton(
            sniff_frame, 
            text="▶ Avvia Cattura", 
            command=self.toggle_sniffer, 
            height=45,
            fg_color="#00cc66",
            hover_color="#00994d"
        )
        self.btn_sniff.pack(pady=5, padx=20)
        
        # Filtro pacchetti
        self.filter_var = ctk.StringVar(value="tcp port 80 or port 21")
        ctk.CTkLabel(sniff_frame, text="Filtro BPF:").pack()
        self.filter_entry = ctk.CTkEntry(sniff_frame, textvariable=self.filter_var)
        self.filter_entry.pack(pady=5, padx=10)
        
        # Bottone esporta
        self.btn_export = ctk.CTkButton(
            sniff_frame,
            text="💾 Esporta Catture",
            command=self.export_packets,
            height=35,
            fg_color="#666666"
        )
        self.btn_export.pack(pady=10, padx=20)
        
        # Sezione Cracking
        crack_frame = ctk.CTkFrame(controls, fg_color="#333333")
        crack_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            crack_frame, 
            text="⚡ Hash Cracker", 
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        
        # Input hash
        ctk.CTkLabel(crack_frame, text="Hash MD5:").pack()
        self.hash_entry = ctk.CTkEntry(
            crack_frame,
            placeholder_text="Inserisci hash MD5..."
        )
        self.hash_entry.pack(pady=5, padx=10)
        
        # Opzioni cracking
        self.use_wordlist = ctk.CTkCheckBox(
            crack_frame,
            text="Usa wordlist comune"
        )
        self.use_wordlist.pack(pady=5)
        self.use_wordlist.select()
        
        self.use_bruteforce = ctk.CTkCheckBox(
            crack_frame,
            text="Bruteforce (max 4 char)"
        )
        self.use_bruteforce.pack(pady=5)
        
        # Bottone crack
        self.btn_crack = ctk.CTkButton(
            crack_frame, 
            text="🔨 Avvia Crack", 
            command=self.toggle_cracker, 
            height=45,
            fg_color="#3b82f6",
            hover_color="#2563eb"
        )
        self.btn_crack.pack(pady=10, padx=20)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(crack_frame)
        self.progress_bar.pack(pady=10, padx=20)
        self.progress_bar.set(0)
        
        # Pulsanti utilità
        ctk.CTkButton(
            controls,
            text="🗑️ Pulisci Log",
            command=self.clear_logs,
            height=35,
            fg_color="#666666"
        ).pack(pady=5, padx=20)

    def create_log_area(self):
        """Crea l'area centrale dei log"""
        log_frame = ctk.CTkFrame(self, fg_color="#1e1e1e")
        log_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)
        
        # Toolbar log
        log_toolbar = ctk.CTkFrame(log_frame, fg_color="#2a2a2a", height=40)
        log_toolbar.pack(fill="x")
        
        ctk.CTkLabel(
            log_toolbar,
            text="📋 Log Attività",
            font=("Arial", 14, "bold")
        ).pack(side="left", padx=10)
        
        self.packet_count = ctk.CTkLabel(
            log_toolbar,
            text="Pacchetti: 0",
            font=("Arial", 12)
        )
        self.packet_count.pack(side="right", padx=10)
        
        # Area log
        self.log_area = ctk.CTkTextbox(
            log_frame,
            font=("Consolas", 12),
            fg_color="#1a1a1a",
            text_color="#00ff00",
            wrap="word"
        )
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Configura tag per colori
        self.log_area.tag_config("error", foreground="#ff4444")
        self.log_area.tag_config("success", foreground="#00ff00")
        self.log_area.tag_config("warning", foreground="#ffaa00")
        self.log_area.tag_config("info", foreground="#00aaff")
        self.log_area.tag_config("data", foreground="#ff69b4")

    def create_stats_panel(self):
        """Crea il pannello statistiche destro"""
        stats = ctk.CTkFrame(self, width=200, fg_color="#2b2b2b")
        stats.grid(row=1, column=2, sticky="ns", padx=(10, 20), pady=10)
        stats.grid_propagate(False)
        
        ctk.CTkLabel(
            stats,
            text="📊 Statistiche",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        
        self.stats_text = ctk.CTkTextbox(
            stats,
            font=("Consolas", 11),
            fg_color="#1a1a1a",
            height=300
        )
        self.stats_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.stats_text.insert("end", "In attesa di attività...\n")
        self.stats_text.configure(state="disabled")

    def log(self, message, level="info"):
        """Aggiunge messaggio alla coda di log"""
        self.log_queue.put((message, level))

    def process_log_queue(self):
        """Processa la coda dei messaggi di log"""
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self._write_log(message, level)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_log_queue)

    def _write_log(self, message, level):
        """Scrive effettivamente il messaggio nel widget di log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_area.insert("end", log_entry, level)
        self.log_area.see("end")

    def toggle_sniffer(self):
        """Avvia/Ferma lo sniffer"""
        if not self.is_sniffing:
            self.start_sniffer()
        else:
            self.stop_sniffer()

    def start_sniffer(self):
        """Avvia la cattura pacchetti"""
        if not SCAPY_AVAILABLE:
            self.log("⚠️ Scapy non disponibile - Avvio modalità simulazione", "warning")
            self.start_simulated_sniffing()
            return
        
        self.is_sniffing = True
        self.btn_sniff.configure(text="■ Ferma Cattura", fg_color="#ff4444")
        self.update_status("In ascolto...", "yellow")
        
        self.sniff_thread = threading.Thread(
            target=self.real_sniffer,
            daemon=True
        )
        self.sniff_thread.start()
        self.log("🔍 Sniffer avviato su interfaccia di rete", "info")

    def stop_sniffer(self):
        """Ferma lo sniffer"""
        self.is_sniffing = False
        self.btn_sniff.configure(text="▶ Avvia Cattura", fg_color="#00cc66")
        self.update_status("Inattivo", "red")
        self.log("⏹️ Sniffer fermato", "info")

    def real_sniffer(self):
        """Sniffer reale usando Scapy"""
        def packet_callback(packet):
            if not self.is_sniffing:
                return False
            
            try:
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    
                    packet_info = {
                        "timestamp": datetime.now().isoformat(),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "TCP"
                    }
                    
                    self.captured_packets.append(packet_info)
                    
                    # Log per HTTP (porta 80)
                    if dst_port == 80 or src_port == 80:
                        self.log(f"🌐 HTTP: {src_ip}:{src_port} → {dst_ip}:{dst_port}", "info")
                        
                        # Cerca credenziali nel payload
                        if packet.haslayer(Raw):
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            self.search_credentials(payload)
                    
                    # Log per FTP (porta 21)
                    elif dst_port == 21 or src_port == 21:
                        self.log(f"📁 FTP: {src_ip}:{src_port} → {dst_ip}:{dst_port}", "data")
                        
                        if packet.haslayer(Raw):
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if 'USER' in payload or 'PASS' in payload:
                                self.log(f"🔑 FTP Credentials: {payload.strip()}", "warning")
                    
                    # Aggiorna contatore
                    self.after(0, self.update_packet_count, len(self.captured_packets))
                    
            except Exception as e:
                self.log(f"Errore elaborazione pacchetto: {e}", "error")
        
        try:
            sniff(prn=packet_callback, store=False, filter=self.filter_var.get())
        except Exception as e:
            self.log(f"Errore sniffer: {e}", "error")
            self.stop_sniffer()

    def start_simulated_sniffing(self):
        """Modalità simulazione per testing"""
        self.is_sniffing = True
        self.btn_sniff.configure(text="■ Ferma Cattura", fg_color="#ff4444")
        self.update_status("Simulazione...", "yellow")
        
        def simulate():
            simulated_packets = [
                {"src": "192.168.1.100:34567", "dst": "93.184.216.34:80", "type": "HTTP"},
                {"src": "10.0.0.15:23456", "dst": "172.16.0.1:21", "type": "FTP"},
                {"src": "192.168.1.101:45678", "dst": "151.101.1.69:80", "type": "HTTP"},
                {"src": "10.0.0.20:12345", "dst": "192.168.1.1:80", "type": "HTTP"},
            ]
            
            for i, packet in enumerate(simulated_packets):
                if not self.is_sniffing:
                    break
                
                time.sleep(1)
                
                if packet["type"] == "HTTP":
                    self.log(f"🌐 HTTP: {packet['src']} → {packet['dst']}", "info")
                    
                    # Simula credenziali trovate
                    if i == 0:
                        self.log("📦 HTTP POST /login", "info")
                        self.log("🔑 Trovate credenziali: admin:password123", "success")
                    elif i == 2:
                        self.log("📦 HTTP GET /api/data", "info")
                        self.log("🔑 Token trovato: Bearer eyJhbGc...", "warning")
                
                elif packet["type"] == "FTP":
                    self.log(f"📁 FTP: {packet['src']} → {packet['dst']}", "data")
                    self.log("📨 Comando: USER ftpuser", "info")
                    time.sleep(0.5)
                    self.log("📨 Comando: PASS ftp123", "info")
                    self.log("🔑 FTP Credentials: ftpuser:ftp123", "success")
                
                # Simula pacchetto catturato
                self.captured_packets.append({
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": packet["src"],
                    "dst_ip": packet["dst"],
                    "type": packet["type"]
                })
                
                self.after(0, self.update_packet_count, len(self.captured_packets))
            
            if self.is_sniffing:
                self.after(1000, simulate)
        
        self.sniff_thread = threading.Thread(target=simulate, daemon=True)
        self.sniff_thread.start()
        self.log("🎭 Avviata simulazione cattura pacchetti", "warning")

    def search_credentials(self, payload):
        """Cerca pattern di credenziali nel payload"""
        keywords = ['username', 'password', 'user', 'pass', 'login', 'email']
        payload_lower = payload.lower()
        
        for keyword in keywords:
            if keyword in payload_lower:
                self.log(f"🔍 Possibili credenziali nel payload:", "warning")
                self.log(f"📄 {payload[:200]}...", "data")
                break

    def toggle_cracker(self):
        """Avvia/Ferma il cracker di hash"""
        if not self.is_cracking:
            self.start_cracker()
        else:
            self.stop_cracker()

    def start_cracker(self):
        """Avvia il processo di cracking"""
        target_hash = self.hash_entry.get().strip().lower()
        
        if not target_hash:
            self.log("❌ Inserire un hash MD5 valido", "error")
            messagebox.showerror("Errore", "Inserire un hash MD5 da craccare")
            return
        
        if len(target_hash) != 32:
            self.log("❌ Hash MD5 non valido (deve essere 32 caratteri)", "error")
            return
        
        self.is_cracking = True
        self.btn_crack.configure(text="■ Ferma Crack", fg_color="#ff4444")
        self.progress_bar.set(0)
        
        self.log(f"🔨 Avvio cracking hash: {target_hash}", "info")
        
        self.crack_thread = threading.Thread(
            target=self.crack_hash,
            args=(target_hash,),
            daemon=True
        )
        self.crack_thread.start()

    def stop_cracker(self):
        """Ferma il processo di cracking"""
        self.is_cracking = False
        self.btn_crack.configure(text="🔨 Avvia Crack", fg_color="#3b82f6")
        self.log("⏹️ Cracking interrotto", "info")

    def crack_hash(self, target_hash):
        """Logica di cracking hash"""
        found = False
        
        # 1. Wordlist comune
        if self.use_wordlist.get() and not found:
            self.log("📚 Tentativo con wordlist comune...", "info")
            total = len(self.common_passwords)
            
            for i, password in enumerate(self.common_passwords):
                if not self.is_cracking:
                    return
                
                progress = (i + 1) / total
                self.after(0, self.progress_bar.set, progress)
                
                hash_attempt = hashlib.md5(password.encode()).hexdigest()
                
                if hash_attempt == target_hash:
                    self.password_found(password, "wordlist")
                    found = True
                    break
                
                if i % 5 == 0:  # Log ogni 5 tentativi
                    self.log(f"🔎 Provando [{i+1}/{total}]: {password}", "info")
                    time.sleep(0.1)
        
        # 2. Bruteforce (solo se selezionato e non trovato)
        if self.use_bruteforce.get() and not found:
            self.log("🔢 Avvio bruteforce (max 4 caratteri)...", "info")
            charset = string.ascii_lowercase + string.digits
            
            for length in range(1, 5):
                if not self.is_cracking:
                    return
                
                total_combinations = len(charset) ** length
                self.log(f"📊 Testando {length} caratteri ({total_combinations} combinazioni)", "info")
                
                for i, combo in enumerate(itertools.product(charset, repeat=length)):
                    if not self.is_cracking:
                        return
                    
                    password = ''.join(combo)
                    progress = i / total_combinations
                    self.after(0, self.progress_bar.set, progress)
                    
                    hash_attempt = hashlib.md5(password.encode()).hexdigest()
                    
                    if hash_attempt == target_hash:
                        self.password_found(password, "bruteforce")
                        found = True
                        break
                    
                    if i % 1000 == 0:
                        self.log(f"🔄 Tentativo #{i}: {password}", "info")
                        time.sleep(0.001)
                
                if found:
                    break
        
        if not found:
            self.log("❌ Password non trovata nei tentativi effettuati", "error")
            self.stop_cracker()
            self.update_status("Fallito", "red")

    def password_found(self, password, method):
        """Gestisce il ritrovamento di una password"""
        self.log("="*50, "success")
        self.log(f"✅ PASSWORD TROVATA!", "success")
        self.log(f"🔓 Password: {password}", "success")
        self.log(f"📊 Metodo: {method}", "success")
        self.log("="*50, "success")
        
        self.update_status("Trovata!", "green")
        self.progress_bar.set(1)
        
        # Mostra popup
        messagebox.showinfo(
            "Password Trovata!",
            f"Hash craccato con successo!\n\nPassword: {password}\nMetodo: {method}"
        )
        
        self.stop_cracker()

    def export_packets(self):
        """Esporta i pacchetti catturati in JSON"""
        if not self.captured_packets:
            messagebox.showwarning("Nessun dato", "Nessun pacchetto da esportare")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.captured_packets, f, indent=2)
                self.log(f"💾 Pacchetti esportati in: {filename}", "success")
                messagebox.showinfo("Successo", f"Esportati {len(self.captured_packets)} pacchetti")
            except Exception as e:
                self.log(f"Errore esportazione: {e}", "error")

    def clear_logs(self):
        """Pulisce l'area dei log"""
        self.log_area.delete("1.0", "end")
        self.captured_packets = []
        self.packet_count.configure(text="Pacchetti: 0")
        self.log("🗑️ Log puliti", "info")

    def update_status(self, status, color):
        """Aggiorna lo stato nell'header"""
        self.lbl_status.configure(text=status)
        self.status_dot.configure(text_color=color)

    def update_packet_count(self, count):
        """Aggiorna il contatore pacchetti"""
        self.packet_count.configure(text=f"Pacchetti: {count}")
        
        # Aggiorna statistiche
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", "end")
        self.stats_text.insert("end", f"📊 Statistiche Correnti\n")
        self.stats_text.insert("end", f"{'='*25}\n")
        self.stats_text.insert("end", f"Pacchetti: {count}\n")
        self.stats_text.insert("end", f"HTTP: {sum(1 for p in self.captured_packets if p.get('type') == 'HTTP')}\n")
        self.stats_text.insert("end", f"FTP: {sum(1 for p in self.captured_packets if p.get('type') == 'FTP')}\n")
        self.stats_text.configure(state="disabled")

    def on_closing(self):
        """Gestisce la chiusura dell'applicazione"""
        self.is_sniffing = False
        self.is_cracking = False
        
        if messagebox.askokcancel("Esci", "Sei sicuro di voler uscire?"):
            self.destroy()

if __name__ == "__main__":
    app = AuraCrack()
    
    # Messaggio di benvenuto
    app.log("="*60, "info")
    app.log("🔓 AuraCrack Pro v1.0 - Network Security Tool", "info")
    app.log("⚠️  Uso consentito solo su reti autorizzate", "warning")
    app.log("="*60, "info")
    
    if not SCAPY_AVAILABLE:
        app.log("📦 Scapy non installato - Modalità simulazione attiva", "warning")
        app.log("💡 Installa con: pip install scapy", "info")
    
    app.mainloop()
