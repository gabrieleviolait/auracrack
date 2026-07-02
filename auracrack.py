"""AuraCrack - utility grafica per audit password autorizzati."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import queue
import re
import socket
import subprocess
import threading
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

try:
    import psutil
except ImportError:  # pragma: no cover - gestito nella GUI
    psutil = None


HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


@dataclass
class AuditResult:
    timestamp: str
    algorithm: str
    target_hash: str
    password: str
    attempts: int


def detect_algorithm(value: str) -> str | None:
    value = value.strip().lower()
    if not value or any(char not in "0123456789abcdef" for char in value):
        return None
    return HASH_ALGORITHMS.get(len(value))


def find_in_wordlist(target: str, algorithm: str, path: Path, stop: threading.Event):
    """Restituisce (password|None, tentativi). Funzione pura e testabile."""
    attempts = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if stop.is_set():
                return None, attempts
            candidate = line.rstrip("\r\n")
            attempts += 1
            digest = hashlib.new(algorithm, candidate.encode("utf-8")).hexdigest()
            if digest == target.lower():
                return candidate, attempts
    return None, attempts


class AuraCrack(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("AuraCrack — Password Audit")
        self.geometry("1180x720")
        self.minsize(940, 620)

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.wordlist: Path | None = None
        self.results: list[AuditResult] = []
        self.arp_baseline: dict[str, str] = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_ui()
        self.after(100, self._drain_events)

    def _build_ui(self):
        header = ctk.CTkFrame(self, corner_radius=0, fg_color="#10161f")
        header.grid(row=0, column=0, columnspan=3, sticky="ew")
        ctk.CTkLabel(header, text="AuraCrack", font=("Segoe UI", 30, "bold"),
                     text_color="#41e6a1").pack(side="left", padx=24, pady=18)
        ctk.CTkLabel(header, text="Audit locale e autorizzato", font=("Segoe UI", 13),
                     text_color="#8ea0b8").pack(side="left")
        self.status = ctk.CTkLabel(header, text="● Pronto", text_color="#8ea0b8")
        self.status.pack(side="right", padx=24)
        credit = ctk.CTkLabel(header, text="Credits: gabrieleviola.it", text_color="#41e6a1", cursor="hand2")
        credit.pack(side="right", padx=8)
        credit.bind("<Button-1>", lambda _event: webbrowser.open("https://gabrieleviola.it/"))

        controls = ctk.CTkFrame(self, width=285, fg_color="#151d28")
        controls.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=16)
        controls.grid_propagate(False)
        ctk.CTkLabel(controls, text="AUDIT HASH", font=("Segoe UI", 12, "bold"),
                     text_color="#8ea0b8").pack(anchor="w", padx=18, pady=(20, 8))
        self.hash_entry = ctk.CTkEntry(controls, placeholder_text="MD5 / SHA-1 / SHA-256 / SHA-512", height=42)
        self.hash_entry.pack(fill="x", padx=18, pady=5)
        self.algorithm_label = ctk.CTkLabel(controls, text="Algoritmo: rilevamento automatico", text_color="#8ea0b8")
        self.algorithm_label.pack(anchor="w", padx=18, pady=(2, 10))
        self.wordlist_button = ctk.CTkButton(controls, text="Scegli wordlist…", command=self.choose_wordlist,
                                             fg_color="#263447", hover_color="#33465f")
        self.wordlist_button.pack(fill="x", padx=18, pady=5)
        self.start_button = ctk.CTkButton(controls, text="Avvia audit", command=self.start_audit,
                                          fg_color="#18a66a", hover_color="#138655", height=44)
        self.start_button.pack(fill="x", padx=18, pady=(14, 5))
        self.stop_button = ctk.CTkButton(controls, text="Interrompi", command=self.stop_audit,
                                         state="disabled", fg_color="#a63d4b")
        self.stop_button.pack(fill="x", padx=18, pady=5)
        ctk.CTkLabel(controls, text="RETE LOCALE", font=("Segoe UI", 12, "bold"),
                     text_color="#8ea0b8").pack(anchor="w", padx=18, pady=(26, 8))
        ctk.CTkButton(controls, text="Mostra interfacce", command=self.show_interfaces,
                      fg_color="#263447", hover_color="#33465f").pack(fill="x", padx=18, pady=5)
        ctk.CTkButton(controls, text="Audit rete difensivo", command=self.start_network_audit,
                      fg_color="#263447", hover_color="#33465f").pack(fill="x", padx=18, pady=5)
        ctk.CTkButton(controls, text="Analizza file PCAP…", command=self.choose_pcap,
                      fg_color="#263447", hover_color="#33465f").pack(fill="x", padx=18, pady=5)
        ctk.CTkLabel(controls, text="Inventario passivo e analisi offline.\nNessuna estrazione di password o MITM.",
                     justify="left", text_color="#71839b", font=("Segoe UI", 11)).pack(anchor="w", padx=18, pady=8)

        center = ctk.CTkFrame(self, fg_color="#111822")
        center.grid(row=1, column=1, sticky="nsew", padx=8, pady=16)
        ctk.CTkLabel(center, text="Attività", font=("Segoe UI", 17, "bold")).pack(anchor="w", padx=16, pady=(16, 6))
        self.log_box = ctk.CTkTextbox(center, font=("Consolas", 12), fg_color="#0b1119", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=16, pady=(4, 10))
        self.log_box.configure(state="disabled")
        ctk.CTkButton(center, text="Pulisci log", width=110, command=self.clear_log,
                      fg_color="transparent", border_width=1).pack(anchor="e", padx=16, pady=(0, 14))

        right = ctk.CTkFrame(self, fg_color="#151d28")
        right.grid(row=1, column=2, sticky="nsew", padx=(8, 16), pady=16)
        ctk.CTkLabel(right, text="Risultati", font=("Segoe UI", 17, "bold")).pack(anchor="w", padx=16, pady=(16, 6))
        self.result_box = ctk.CTkTextbox(right, font=("Consolas", 12), fg_color="#0b1119", wrap="word")
        self.result_box.pack(fill="both", expand=True, padx=16, pady=(4, 10))
        self.result_box.configure(state="disabled")
        ctk.CTkButton(right, text="Esporta CSV", command=self.export_csv,
                      fg_color="#263447", hover_color="#33465f").pack(fill="x", padx=16, pady=(0, 14))

    def _write(self, widget, text: str):
        widget.configure(state="normal")
        widget.insert("end", text + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def log(self, text: str):
        self._write(self.log_box, f"[{time.strftime('%H:%M:%S')}] {text}")

    def clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def choose_wordlist(self):
        value = filedialog.askopenfilename(title="Scegli una wordlist", filetypes=[("File di testo", "*.txt"), ("Tutti i file", "*.*")])
        if value:
            self.wordlist = Path(value)
            self.wordlist_button.configure(text=self.wordlist.name)
            self.log(f"Wordlist selezionata: {self.wordlist}")

    def start_audit(self):
        target = self.hash_entry.get().strip().lower()
        algorithm = detect_algorithm(target)
        if not algorithm:
            messagebox.showerror("Hash non valido", "Inserisci un hash esadecimale MD5, SHA-1, SHA-256 o SHA-512.")
            return
        if not self.wordlist or not self.wordlist.is_file():
            messagebox.showerror("Wordlist mancante", "Scegli prima un file wordlist leggibile.")
            return
        if self.worker and self.worker.is_alive():
            return
        if not messagebox.askyesno("Conferma autorizzazione", "Confermi di essere autorizzato a verificare questo hash?"):
            return
        self.algorithm_label.configure(text=f"Algoritmo: {algorithm.upper()}")
        self.stop_event.clear()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status.configure(text="● Audit in corso", text_color="#41e6a1")
        self.log(f"Avvio audit {algorithm.upper()} su {self.wordlist.name}")
        self.worker = threading.Thread(target=self._audit_worker, args=(target, algorithm, self.wordlist), daemon=True)
        self.worker.start()

    def _audit_worker(self, target: str, algorithm: str, path: Path):
        started = time.perf_counter()
        try:
            password, attempts = find_in_wordlist(target, algorithm, path, self.stop_event)
            self.events.put(("done", (target, algorithm, password, attempts, time.perf_counter() - started)))
        except (OSError, ValueError) as exc:
            self.events.put(("error", str(exc)))

    def stop_audit(self):
        self.stop_event.set()
        self.log("Interruzione richiesta…")

    def _drain_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "done":
                    target, algorithm, password, attempts, elapsed = payload
                    if self.stop_event.is_set() and password is None:
                        self.log(f"Audit interrotto dopo {attempts:,} tentativi")
                    elif password is None:
                        self.log(f"Nessuna corrispondenza ({attempts:,} tentativi, {elapsed:.2f}s)")
                    else:
                        result = AuditResult(time.strftime("%Y-%m-%d %H:%M:%S"), algorithm, target, password, attempts)
                        self.results.append(result)
                        masked = "•" * max(8, len(password))
                        self._write(self.result_box, f"{algorithm.upper()}  {target[:16]}…\nPassword: {masked}  |  Tentativi: {attempts:,}\n")
                        self.log(f"Corrispondenza trovata dopo {attempts:,} tentativi ({elapsed:.2f}s); valore mascherato")
                    self._set_idle()
                elif kind == "error":
                    self.log(f"Errore: {payload}")
                    messagebox.showerror("Errore audit", str(payload))
                    self._set_idle()
                elif kind == "log":
                    self.log(str(payload))
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _set_idle(self):
        self.status.configure(text="● Pronto", text_color="#8ea0b8")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def show_interfaces(self):
        if psutil is None:
            messagebox.showerror("Dipendenza mancante", "Installa psutil: pip install -r requirements.txt")
            return
        self.log("Interfacce e indirizzi locali:")
        for name, addresses in psutil.net_if_addrs().items():
            values = []
            for address in addresses:
                try:
                    ip = ipaddress.ip_address(address.address.split("%", 1)[0])
                    if not ip.is_loopback:
                        values.append(str(ip))
                except ValueError:
                    continue
            if values:
                self.log(f"  {name}: {', '.join(values)}")
        self.log(f"Hostname: {socket.gethostname()}")

    def start_network_audit(self):
        if not messagebox.askyesno("Conferma autorizzazione", "Confermi di essere autorizzato ad analizzare questo computer e la rete locale?"):
            return
        threading.Thread(target=self._network_audit_worker, daemon=True).start()

    def _network_audit_worker(self):
        self.events.put(("log", "Audit difensivo della rete avviato"))
        if psutil is None:
            self.events.put(("error", "psutil non è installato"))
            return
        listening = []
        insecure = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN and conn.laddr:
                    listening.append(f"{conn.laddr.ip}:{conn.laddr.port}")
                if conn.raddr and conn.raddr.port in {20, 21, 23, 80}:
                    insecure.append(f"{conn.laddr.ip}:{conn.laddr.port} → {conn.raddr.ip}:{conn.raddr.port}")
        except (psutil.AccessDenied, OSError) as exc:
            self.events.put(("log", f"Connessioni parzialmente disponibili: {exc}"))
        self.events.put(("log", f"Porte locali in ascolto ({len(listening)}): {', '.join(listening[:20]) or 'nessuna'}"))
        if len(listening) > 20:
            self.events.put(("log", f"…e altre {len(listening) - 20} porte"))
        self.events.put(("log", f"Connessioni su protocolli non cifrati ({len(insecure)}): {', '.join(insecure) or 'nessuna'}"))

        entries = self._read_arp_cache()
        self.events.put(("log", f"Dispositivi nella cache ARP ({len(entries)}):"))
        for ip, mac in entries.items():
            previous = self.arp_baseline.get(ip)
            warning = f"  ⚠ MAC cambiato (prima {previous})" if previous and previous != mac else ""
            self.events.put(("log", f"  {ip} — {mac}{warning}"))
        self.arp_baseline.update(entries)
        self.events.put(("log", "Audit rete completato. Ripetilo per rilevare variazioni IP↔MAC."))

    @staticmethod
    def _read_arp_cache() -> dict[str, str]:
        """Legge la cache ARP del sistema senza inviare pacchetti."""
        try:
            output = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                    encoding="utf-8", errors="ignore", timeout=8).stdout
        except (OSError, subprocess.SubprocessError):
            return {}
        entries = {}
        pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:-]{17})\b")
        for ip, mac in pattern.findall(output):
            try:
                if not ipaddress.ip_address(ip).is_multicast:
                    entries[ip] = mac.lower().replace("-", ":")
            except ValueError:
                continue
        return entries

    def choose_pcap(self):
        path = filedialog.askopenfilename(title="Scegli una cattura", filetypes=[("Packet capture", "*.pcap *.pcapng"), ("Tutti i file", "*.*")])
        if path:
            threading.Thread(target=self._pcap_worker, args=(Path(path),), daemon=True).start()

    def _pcap_worker(self, path: Path):
        try:
            from scapy.all import ARP, IP, IPv6, TCP, UDP, PcapReader
        except ImportError:
            self.events.put(("error", "Scapy non è installato. Esegui il launcher per installare requirements.txt."))
            return
        packets = tcp = udp = insecure = 0
        hosts: set[str] = set()
        arp_seen: dict[str, set[str]] = {}
        try:
            with PcapReader(str(path)) as reader:
                for packet in reader:
                    packets += 1
                    if IP in packet:
                        hosts.update((packet[IP].src, packet[IP].dst))
                    elif IPv6 in packet:
                        hosts.update((packet[IPv6].src, packet[IPv6].dst))
                    if TCP in packet:
                        tcp += 1
                        if packet[TCP].sport in {20, 21, 23, 80} or packet[TCP].dport in {20, 21, 23, 80}:
                            insecure += 1
                    if UDP in packet:
                        udp += 1
                    if ARP in packet and packet[ARP].psrc and packet[ARP].hwsrc:
                        arp_seen.setdefault(packet[ARP].psrc, set()).add(packet[ARP].hwsrc.lower())
        except (OSError, ValueError) as exc:
            self.events.put(("error", f"Impossibile leggere il PCAP: {exc}"))
            return
        anomalies = [f"{ip}: {', '.join(sorted(macs))}" for ip, macs in arp_seen.items() if len(macs) > 1]
        self.events.put(("log", f"PCAP {path.name}: {packets:,} pacchetti, {tcp:,} TCP, {udp:,} UDP, {len(hosts)} host"))
        self.events.put(("log", f"Traffico su porte HTTP/FTP/Telnet: {insecure:,} pacchetti (contenuto non ispezionato)"))
        self.events.put(("log", "Possibili conflitti ARP: " + ("; ".join(anomalies) if anomalies else "nessuno")))

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Nessun risultato", "Non ci sono risultati da esportare.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="auracrack-results.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(["timestamp", "algorithm", "hash", "password", "attempts"])
                for item in self.results:
                    writer.writerow([item.timestamp, item.algorithm, item.target_hash, item.password, item.attempts])
            self.log(f"Risultati esportati: {path}")
        except OSError as exc:
            messagebox.showerror("Esportazione fallita", str(exc))


if __name__ == "__main__":
    AuraCrack().mainloop()
