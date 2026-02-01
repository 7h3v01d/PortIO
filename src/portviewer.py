import socket
import psutil
import subprocess
import re
import os
from tkinter import ttk, messagebox
import tkinter as tk
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
from datetime import datetime


class PortManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Manager - Enhanced")
        self.root.geometry("1000x650")
        
        # Style configuration
        self.style = ttkb.Style(theme="darkly")
        
        # Initialize attributes
        self.log_file = "port_logs.txt"
        self.status_var = tk.StringVar()
        
        # Create widgets
        self.create_widgets()
        
        # Initialize log file
        self.init_log_file()
        
        # Initial port scan
        self.refresh_ports()

    def init_log_file(self):
        """Initialize the log file with headers"""
        with open(self.log_file, 'a') as f:
            f.write("\n" + "="*50 + "\n")
            f.write(f"Enhanced Port Manager Log - {self.get_current_time()}\n")
            f.write("="*50 + "\n\n")

    def get_current_time(self):
        """Get current time in YYYY-MM-DD HH:MM:SS format"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def create_widgets(self):
        """Create and arrange all widgets"""
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=BOTH, expand=YES)
        
        # Title label
        self.title_label = ttk.Label(
            self.main_frame, 
            text="Enhanced Port Manager", 
            font=('Helvetica', 16, 'bold')
        )
        self.title_label.pack(pady=10)
        
        # Control buttons frame
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=X, pady=10)
        
        # Refresh button
        self.refresh_btn = ttk.Button(
            self.control_frame,
            text="Refresh Ports",
            command=self.refresh_ports,
            bootstyle=SUCCESS
        )
        self.refresh_btn.pack(side=LEFT, padx=5)
        
        # Check specific port
        self.port_check_frame = ttk.Frame(self.control_frame)
        self.port_check_frame.pack(side=LEFT, padx=10)
        
        self.port_entry = ttk.Entry(self.port_check_frame, width=10)
        self.port_entry.pack(side=LEFT, padx=5)
        
        self.check_port_btn = ttk.Button(
            self.port_check_frame,
            text="Check Port",
            command=self.check_specific_port,
            bootstyle=INFO
        )
        self.check_port_btn.pack(side=LEFT)
        
        # Save to file button
        self.save_btn = ttk.Button(
            self.control_frame,
            text="Save to File",
            command=self.save_to_file,
            bootstyle=WARNING
        )
        self.save_btn.pack(side=LEFT, padx=10)
        
        # Treeview frame
        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill=BOTH, expand=YES)
        
        # Treeview scrollbar
        self.scrollbar = ttk.Scrollbar(self.tree_frame)
        self.scrollbar.pack(side=RIGHT, fill=Y)
        
        # Create treeview with enhanced columns
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=('Port', 'Status', 'Process', 'PID', 'Protocol', 'Local Address', 'Remote Address'),
            show='headings',
            yscrollcommand=self.scrollbar.set
        )
        self.scrollbar.config(command=self.tree.yview)
        
        # Configure columns
        columns = {
            'Port': 80,
            'Status': 120,
            'Process': 200,
            'PID': 80,
            'Protocol': 100,
            'Local Address': 150,
            'Remote Address': 150
        }
        
        for col, width in columns.items():
            self.tree.column(col, width=width, anchor=CENTER)
            self.tree.heading(col, text=col)
        
        self.tree.pack(fill=BOTH, expand=YES)
        
        # Status bar
        self.status_bar = ttk.Label(
            self.main_frame,
            textvariable=self.status_var,
            relief=SUNKEN,
            anchor=W
        )
        self.status_bar.pack(fill=X, pady=(10, 0))

    def refresh_ports(self):
        """Scan and display all ports with their states"""
        self.status_var.set("Scanning all TCP connections...")
        self.root.update()
        
        # Clear existing data
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get all connections
        connections = self.get_all_connections()
        
        # Populate treeview
        for conn in connections:
            self.tree.insert('', END, values=(
                conn['port'],
                conn['status'],
                conn['name'],
                conn['pid'],
                conn['protocol'],
                f"{conn['local_address']}:{conn['port']}",
                f"{conn['remote_address']}:{conn['remote_port']}" if conn['remote_address'] else ""
            ))
        
        self.status_var.set(f"Found {len(connections)} connections. Updated: {self.get_current_time()}")

    def get_all_connections(self):
        """Get all TCP connections with detailed information"""
        connections = []
        
        for conn in psutil.net_connections(kind='tcp'):
            if conn.laddr:
                try:
                    proc = psutil.Process(conn.pid)
                    name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    name = "System"
                
                connections.append({
                    'port': conn.laddr.port,
                    'status': conn.status,
                    'name': name,
                    'pid': conn.pid,
                    'protocol': 'TCP',
                    'local_address': conn.laddr.ip,
                    'remote_address': conn.raddr.ip if conn.raddr else "",
                    'remote_port': conn.raddr.port if conn.raddr else 0
                })
        
        return connections

    def check_specific_port(self):
        """Check status of a specific port"""
        port_str = self.port_entry.get()
        if not port_str.isdigit():
            self.status_var.set("Please enter a valid port number")
            return
            
        port = int(port_str)
        if not (0 < port <= 65535):
            self.status_var.set("Port must be between 1 and 65535")
            return
            
        # Clear selection
        for item in self.tree.selection():
            self.tree.selection_remove(item)
            
        # Find and highlight matching ports
        found = False
        for item in self.tree.get_children():
            if int(self.tree.item(item, 'values')[0]) == port:
                self.tree.selection_add(item)
                self.tree.see(item)
                found = True
                
        if found:
            self.status_var.set(f"Found port {port} in listed connections")
        else:
            self.status_var.set(f"Port {port} not found in active connections")

    def save_to_file(self):
        """Save all connection data to file"""
        try:
            filename = f"port_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            connections = self.get_all_connections()
            
            with open(filename, 'w') as f:
                f.write(f"Enhanced Port Scan - {self.get_current_time()}\n")
                f.write("="*80 + "\n")
                f.write("{:<8} {:<12} {:<21} {:<21} {:<12} {:<8} {}\n".format(
                    "Proto", "Local", "Foreign", "State", "PID", "Port", "Process"
                ))
                f.write("="*80 + "\n")
                
                for conn in connections:
                    f.write("{:<8} {:<21} {:<21} {:<12} {:<8} {:<8} {}\n".format(
                        conn['protocol'],
                        f"{conn['local_address']}:{conn['port']}",
                        f"{conn['remote_address']}:{conn['remote_port']}" if conn['remote_address'] else "*:*",
                        conn['status'],
                        conn['pid'],
                        conn['port'],
                        conn['name']
                    ))
            
            messagebox.showinfo(
                "Save Complete",
                f"Saved {len(connections)} connections to {filename}"
            )
            
        except Exception as e:
            messagebox.showerror(
                "Save Error",
                f"Failed to save connections: {str(e)}"
            )

    def is_port_available(self, port):
        """Check if a port is available for binding"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("0.0.0.0", port))
                return True
            except socket.error:
                return False


if __name__ == "__main__":
    root = ttkb.Window(themename="darkly")
    app = PortManagerApp(root)
    root.mainloop()