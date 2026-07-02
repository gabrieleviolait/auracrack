from __future__ import annotations

import csv
import hashlib
import queue
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


class PasswordAuditFrame(ctk.CTkFrame):
    def __init__(self, master, set_status):
        super().__init__(master, fg_color="transparent")
        self.set_status = set_status
        self.wordlist: Path | None = None
        self.stop_event = threading.Event()
        self.events = queue.Queue()
        self.results = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(self, text="Password Audit", font=("Segoe UI", 24, "bold")).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 4))
        ctk.CTkLabel(self, text="Verifica locale di hash tramite wordlist autorizzate.", text_color="#8ea0b8").grid(row=1, column=0, sticky="w", padx=20)
        body = ctk.CTkFrame(self, fg_color="#151d28")
        body.grid(row=2, column=0, sticky="nsew", padx=20, pady=18)
        body.grid_columnconfigure(1, weight=1); body.grid_rowconfigure(3, weight=1)
        self.hash_entry = ctk.CTkEntry(body, placeholder_text="MD5 / SHA-1 / SHA-256 / SHA-512", height=42)
        self.hash_entry.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(16, 8))
        self.pick = ctk.CTkButton(body, text="Scegli wordlist…", command=self.choose, fg_color="#263447")
        self.pick.grid(row=1, column=0, sticky="ew", padx=(16, 8), pady=8)
        self.run = ctk.CTkButton(body, text="Avvia audit", command=self.start, fg_color="#18a66a")
        self.run.grid(row=1, column=1, sticky="ew", padx=(8, 16), pady=8)
        self.stop = ctk.CTkButton(body, text="Interrompi", command=self.stop_event.set, state="disabled", fg_color="#a63d4b")
        self.stop.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=8)
        self.output = ctk.CTkTextbox(body, font=("Consolas", 12), fg_color="#0b1119")
        self.output.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=16, pady=8)
        ctk.CTkButton(body, text="Esporta CSV", command=self.export, fg_color="#263447").grid(row=4, column=0, columnspan=2, sticky="ew", padx=16, pady=(8, 16))
        self.after(100, self.drain)

    def log(self, text): self.output.insert("end", f"[{time.strftime('%H:%M:%S')}] {text}\n"); self.output.see("end")
    def choose(self):
        path = filedialog.askopenfilename(filetypes=[("Wordlist", "*.txt"), ("Tutti i file", "*.*")])
        if path: self.wordlist = Path(path); self.pick.configure(text=self.wordlist.name)
    def start(self):
        target = self.hash_entry.get().strip().lower()
        algo = ALGORITHMS.get(len(target)) if all(c in "0123456789abcdef" for c in target) else None
        if not algo: messagebox.showerror("Hash non valido", "Inserisci un hash esadecimale supportato."); return
        if not self.wordlist or not self.wordlist.is_file(): messagebox.showerror("Wordlist", "Scegli una wordlist."); return
        if not messagebox.askyesno("Autorizzazione", "Confermi di essere autorizzato a verificare questo hash?"): return
        self.stop_event.clear(); self.run.configure(state="disabled"); self.stop.configure(state="normal")
        self.set_status("Audit hash in corso", "#41e6a1")
        threading.Thread(target=self.worker, args=(target, algo, self.wordlist), daemon=True).start()
    def worker(self, target, algo, path):
        try:
            with path.open(encoding="utf-8", errors="ignore") as stream:
                for count, line in enumerate(stream, 1):
                    if self.stop_event.is_set(): self.events.put(("done", None, count)); return
                    value = line.rstrip("\r\n")
                    if hashlib.new(algo, value.encode()).hexdigest() == target:
                        self.events.put(("found", (time.strftime("%F %T"), algo, target, value, count), count)); return
            self.events.put(("done", None, count if 'count' in locals() else 0))
        except OSError as exc: self.events.put(("error", str(exc), 0))
    def drain(self):
        try:
            while True:
                kind, data, count = self.events.get_nowait()
                if kind == "found": self.results.append(data); self.log(f"Corrispondenza trovata dopo {count:,} tentativi: {'•' * max(8, len(data[3]))}")
                elif kind == "error": self.log(f"Errore: {data}")
                else: self.log(f"Audit terminato dopo {count:,} tentativi")
                self.run.configure(state="normal"); self.stop.configure(state="disabled"); self.set_status("Pronto", "#8ea0b8")
        except queue.Empty: pass
        self.after(100, self.drain)
    def export(self):
        if not self.results: messagebox.showinfo("Risultati", "Nessun risultato da esportare."); return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w=csv.writer(f); w.writerow(["timestamp","algorithm","hash","password","attempts"]); w.writerows(self.results)
