import webbrowser
import customtkinter as ctk
from aura_suite import __version__
from aura_suite.password_audit import PasswordAuditFrame
from aura_suite.network_scanner import NetworkScannerFrame
from aura_suite.traffic_monitor import TrafficMonitorFrame

class AuraSuite(ctk.CTk):
    def __init__(self):
        super().__init__(); ctk.set_appearance_mode("dark"); ctk.set_default_color_theme("blue")
        self.title(f"Aura Security Suite {__version__}"); self.geometry("1120x760"); self.minsize(900,620)
        self.grid_columnconfigure(0,weight=1); self.grid_rowconfigure(1,weight=1)
        header=ctk.CTkFrame(self,corner_radius=0,fg_color="#10161f"); header.grid(row=0,column=0,sticky="ew")
        ctk.CTkLabel(header,text="AURA",font=("Segoe UI",28,"bold"),text_color="#41e6a1").pack(side="left",padx=(22,4),pady=16)
        ctk.CTkLabel(header,text="SECURITY SUITE",font=("Segoe UI",14,"bold"),text_color="#8ea0b8").pack(side="left")
        self.status=ctk.CTkLabel(header,text="● Pronto",text_color="#8ea0b8"); self.status.pack(side="right",padx=22)
        credit=ctk.CTkLabel(header,text="Credits: gabrieleviola.it",text_color="#41e6a1",cursor="hand2")
        credit.pack(side="right",padx=8); credit.bind("<Button-1>",lambda _e:webbrowser.open("https://gabrieleviola.it/"))
        tabs=ctk.CTkTabview(self,fg_color="#111822",segmented_button_selected_color="#18a66a"); tabs.grid(row=1,column=0,sticky="nsew",padx=14,pady=14)
        for name in ("Password Audit","Network Scanner","Traffic Monitor"): tabs.add(name); tabs.tab(name).grid_columnconfigure(0,weight=1); tabs.tab(name).grid_rowconfigure(0,weight=1)
        PasswordAuditFrame(tabs.tab("Password Audit"),self.set_status).grid(row=0,column=0,sticky="nsew")
        NetworkScannerFrame(tabs.tab("Network Scanner"),self.set_status).grid(row=0,column=0,sticky="nsew")
        TrafficMonitorFrame(tabs.tab("Traffic Monitor"),self.set_status).grid(row=0,column=0,sticky="nsew")
    def set_status(self,text,color): self.status.configure(text=f"● {text}",text_color=color)

if __name__=="__main__": AuraSuite().mainloop()
