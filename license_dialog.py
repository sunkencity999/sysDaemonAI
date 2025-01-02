import tkinter as tk
from tkinter import ttk, messagebox
from license_manager import LicenseManager
import sys
import webbrowser

class LicenseDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.license_manager = LicenseManager()
        
        self.title("SysDaemon AI License Activation")
        self.geometry("500x400")
        self.resizable(False, False)
        
        # Make this window modal
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
        # Center the dialog
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', padx=20, pady=(20,10))
        
        ttk.Label(header_frame, 
                 text="Welcome to SysDaemon AI",
                 font=('Helvetica', 16, 'bold')).pack()
                 
        # License Status
        status_frame = ttk.Frame(self)
        status_frame.pack(fill='x', padx=20, pady=10)
        
        license_info = self.license_manager.get_license_info()
        if license_info and license_info.get('valid'):
            status_text = f"Licensed - {license_info['tier'].title()} Edition\nExpires: {license_info['expires_at']}"
            status_color = 'green'
        else:
            status_text = "No Valid License Found"
            status_color = 'red'
            
        ttk.Label(status_frame, 
                 text=status_text,
                 foreground=status_color).pack()
        
        # License Key Entry
        entry_frame = ttk.Frame(self)
        entry_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(entry_frame, 
                 text="Enter License Key:").pack(anchor='w')
        
        self.license_key = tk.Text(entry_frame, height=4, width=40, wrap='word')
        self.license_key.pack(fill='x', pady=(5,0))
        
        # Buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill='x', padx=20, pady=20)
        
        ttk.Button(button_frame, 
                  text="Activate License",
                  command=self.activate_license).pack(side='left', padx=5)
                  
        ttk.Button(button_frame,
                  text="Purchase License",
                  command=self.purchase_license).pack(side='left', padx=5)
                  
        if not (license_info and license_info.get('valid')):
            ttk.Button(button_frame,
                      text="Continue Trial",
                      command=self.continue_trial).pack(side='right', padx=5)
        
    def activate_license(self):
        license_key = self.license_key.get("1.0", "end-1c").strip()
        if not license_key:
            messagebox.showerror("Error", "Please enter a license key")
            return
            
        result = self.license_manager.install_license(license_key)
        if result['status'] == 'success':
            messagebox.showinfo("Success", "License activated successfully!")
            self.destroy()
        else:
            messagebox.showerror("Error", f"Failed to activate license: {result['message']}")
    
    def purchase_license(self):
        messagebox.showinfo("Purchase License",
                          "You will now be redirected to sysDaemonAI.com\n\n"
                          "Available License Tiers:\n"
                          "• Individual: $30/year\n"
                          "• Professional: $99/year\n"
                          "• Enterprise: Starting at $1,499/year")
        webbrowser.open('https://sysDaemonAI.com')
        
    def continue_trial(self):
        if messagebox.askyesno("Continue Trial", 
                             "Would you like to continue using SysDaemon AI in trial mode?\n\n"
                             "Note: Some features may be limited."):
            self.destroy()
            
    def on_closing(self):
        if not self.license_manager.get_license_info():
            if not messagebox.askyesno("Exit", 
                                     "No valid license found. Exit application?"):
                return
        self.destroy()
        if not self.license_manager.get_license_info():
            sys.exit(0)
