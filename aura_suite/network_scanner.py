from __future__ import annotations
import ipaddress, queue, socket, threading, time
import customtkinter as ctk
from tkinter import messagebox

SERVICES={21:"FTP",22:"SSH",23:"Telnet",80:"HTTP",443:"HTTPS",445:"SMB",515:"LPD",631:"IPP",3389:"RDP",8080:"HTTP-ALT",9100:"JetDirect"}

class NetworkScannerFrame(ctk.CTkFrame):
    def __init__(self, master, set_status):
        super().__init__(master, fg_color="transparent"); self.set_status=set_status; self.events=queue.Queue(); self.stop=threading.Event()
        self.grid_columnconfigure(0,weight=1); self.grid_rowconfigure(3,weight=1)
        ctk.CTkLabel(self,text="Network Scanner",font=("Segoe UI",24,"bold")).grid(row=0,column=0,sticky="w",padx=20,pady=(18,4))
        ctk.CTkLabel(self,text="Inventario TCP limitato alla rete privata autorizzata.",text_color="#8ea0b8").grid(row=1,column=0,sticky="w",padx=20)
        bar=ctk.CTkFrame(self,fg_color="#151d28"); bar.grid(row=2,column=0,sticky="ew",padx=20,pady=14); bar.grid_columnconfigure(0,weight=1)
        self.target=ctk.CTkEntry(bar,placeholder_text="Rete privata, es. 192.168.1.0/24"); self.target.grid(row=0,column=0,sticky="ew",padx=12,pady=12)
        ctk.CTkButton(bar,text="Rileva",width=80,command=self.detect,fg_color="#263447").grid(row=0,column=1,padx=4)
        ctk.CTkButton(bar,text="Scan veloce",command=lambda:self.start(False),fg_color="#18a66a").grid(row=0,column=2,padx=4)
        ctk.CTkButton(bar,text="Audit completo",command=lambda:self.start(True),fg_color="#3b82f6").grid(row=0,column=3,padx=(4,12))
        self.output=ctk.CTkTextbox(self,font=("Consolas",12),fg_color="#0b1119"); self.output.grid(row=3,column=0,sticky="nsew",padx=20,pady=(0,20)); self.after(100,self.drain); self.detect()
    def detect(self):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try: s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; self.target.delete(0,"end"); self.target.insert(0,str(ipaddress.ip_network(f"{ip}/24",strict=False)))
        except OSError: pass
        finally: s.close()
    def start(self, deep):
        try: net=ipaddress.ip_network(self.target.get().strip(),strict=False)
        except ValueError: messagebox.showerror("Rete non valida","Inserisci una rete IPv4 CIDR valida."); return
        if net.version!=4 or not net.is_private or net.num_addresses>256: messagebox.showerror("Ambito non consentito","Usa una rete IPv4 privata non più grande di /24."); return
        if not messagebox.askyesno("Autorizzazione",f"Confermi di essere autorizzato a scansionare {net}?"): return
        self.output.delete("1.0","end"); self.set_status("Scansione in corso","#facc15"); threading.Thread(target=self.worker,args=(net,deep),daemon=True).start()
    def worker(self,net,deep):
        ports=list(SERVICES) if deep else [80,443,445,9100]
        for host in list(net.hosts()):
            found=[]
            for port in ports:
                try:
                    with socket.create_connection((str(host),port),timeout=.12): found.append(port)
                except OSError: pass
            if found: self.events.put("%s  %s"%(host,", ".join(f"{p}/{SERVICES[p]}" for p in found)))
        self.events.put(None)
    def drain(self):
        try:
            while True:
                item=self.events.get_nowait()
                if item is None: self.output.insert("end","Scansione completata.\n"); self.set_status("Pronto","#8ea0b8")
                else: self.output.insert("end",item+"\n")
        except queue.Empty: pass
        self.after(100,self.drain)
