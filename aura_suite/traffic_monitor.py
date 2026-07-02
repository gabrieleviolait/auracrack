from __future__ import annotations
import json, queue, threading, time
from tkinter import filedialog, messagebox
import customtkinter as ctk

class TrafficMonitorFrame(ctk.CTkFrame):
    def __init__(self,master,set_status):
        super().__init__(master,fg_color="transparent"); self.set_status=set_status; self.running=False; self.events=queue.Queue(); self.rows=[]
        self.grid_columnconfigure(0,weight=1); self.grid_rowconfigure(3,weight=1)
        ctk.CTkLabel(self,text="Traffic Monitor",font=("Segoe UI",24,"bold")).grid(row=0,column=0,sticky="w",padx=20,pady=(18,4))
        ctk.CTkLabel(self,text="Metadati TCP in tempo reale; nessun payload o credenziale viene mostrato.",text_color="#8ea0b8").grid(row=1,column=0,sticky="w",padx=20)
        bar=ctk.CTkFrame(self,fg_color="#151d28"); bar.grid(row=2,column=0,sticky="ew",padx=20,pady=14); bar.grid_columnconfigure(0,weight=1)
        self.filter=ctk.CTkEntry(bar); self.filter.insert(0,"tcp"); self.filter.grid(row=0,column=0,sticky="ew",padx=12,pady=12)
        self.button=ctk.CTkButton(bar,text="Avvia",command=self.toggle,fg_color="#18a66a"); self.button.grid(row=0,column=1,padx=4)
        ctk.CTkButton(bar,text="Esporta JSON",command=self.export,fg_color="#263447").grid(row=0,column=2,padx=(4,12))
        self.output=ctk.CTkTextbox(self,font=("Consolas",12),fg_color="#0b1119"); self.output.grid(row=3,column=0,sticky="nsew",padx=20,pady=(0,20)); self.after(100,self.drain)
    def toggle(self):
        if self.running: self.running=False; self.button.configure(text="Avvia",fg_color="#18a66a"); self.set_status("Pronto","#8ea0b8"); return
        if not messagebox.askyesno("Autorizzazione","Confermi di essere autorizzato a monitorare questa interfaccia?"): return
        self.running=True; self.button.configure(text="Ferma",fg_color="#a63d4b"); self.set_status("Monitoraggio attivo","#facc15"); threading.Thread(target=self.worker,daemon=True).start()
    def worker(self):
        try:
            from scapy.all import IP,TCP,sniff
            def callback(p):
                if IP in p and TCP in p:
                    row={"timestamp":time.strftime("%FT%T"),"src":p[IP].src,"sport":p[TCP].sport,"dst":p[IP].dst,"dport":p[TCP].dport}
                    self.rows.append(row); self.events.put(f"{row['src']}:{row['sport']} → {row['dst']}:{row['dport']}")
            while self.running: sniff(filter=self.filter.get(),prn=callback,store=False,timeout=1)
        except Exception as exc: self.events.put(f"ERRORE: {exc}"); self.running=False
    def drain(self):
        try:
            while True: self.output.insert("end",self.events.get_nowait()+"\n"); self.output.see("end")
        except queue.Empty: pass
        self.after(100,self.drain)
    def export(self):
        if not self.rows: messagebox.showinfo("Dati","Nessun metadato da esportare."); return
        path=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")])
        if path:
            with open(path,"w",encoding="utf-8") as f: json.dump(self.rows,f,indent=2)
