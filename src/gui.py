import tkinter as tk
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
from tkinter import ttk, messagebox, scrolledtext, Menu, filedialog
from core import PortManager

class PortManagerGUI:
    def __init__(self, root):
        self.root = root
        self.app = PortManager()
        self.create_widgets()
        self.refresh_ports()

    def create_widgets(self):
        """Create and arrange all GUI widgets"""
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=tk.YES)
        
        self.title_label = ttk.Label(self.main_frame, text="Netstat Clone - Enhanced Port Manager", font=('Helvetica', 16, 'bold'))
        self.title_label.pack(pady=10)
        
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=10)
        
        self.refresh_btn = ttk.Button(self.control_frame, text="Refresh Connections", command=self.refresh_ports, bootstyle=SUCCESS)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        self.monitor_btn = ttk.Button(self.control_frame, text="Start Monitoring", command=self.toggle_monitoring, bootstyle=SECONDARY)
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.port_check_frame = ttk.Frame(self.control_frame)
        self.port_check_frame.pack(side=tk.LEFT, padx=10)
        
        self.port_entry = ttk.Entry(self.port_check_frame, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.check_port_btn = ttk.Button(self.port_check_frame, text="Check Port", command=self.check_specific_port_wrapper, bootstyle=INFO)
        self.check_port_btn.pack(side=tk.LEFT)
        
        self.save_btn = ttk.Button(self.control_frame, text="Save to File", command=self.save_to_file, bootstyle=WARNING)
        self.save_btn.pack(side=tk.LEFT, padx=10)
        
        self.netstat_btn = ttk.Button(self.control_frame, text="Show Netstat Output", command=self.show_netstat_output, bootstyle=PRIMARY)
        self.netstat_btn.pack(side=tk.LEFT, padx=10)
        
        self.server_frame = ttk.Frame(self.control_frame)
        self.server_frame.pack(side=tk.LEFT, padx=10)
        
        self.server_port_entry = ttk.Entry(self.server_frame, width=10)
        self.server_port_entry.pack(side=tk.LEFT, padx=5)
        
        self.protocol_var = tk.StringVar(value="TCP")
        self.protocol_menu = ttk.OptionMenu(self.server_frame, self.protocol_var, "TCP", "TCP", "UDP")
        self.protocol_menu.pack(side=tk.LEFT, padx=5)
        
        self.start_server_btn = ttk.Button(self.server_frame, text="Start Server", command=self.start_server_wrapper, bootstyle=SUCCESS)
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_server_btn = ttk.Button(self.server_frame, text="Stop Server", command=self.stop_server_wrapper, bootstyle=DANGER, state=tk.DISABLED)
        self.stop_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.reservation_frame = ttk.Frame(self.control_frame)
        self.reservation_frame.pack(side=tk.LEFT, padx=10)
        
        self.reserve_port_entry = ttk.Entry(self.reservation_frame, width=10)
        self.reserve_port_entry.pack(side=tk.LEFT, padx=5)
        
        self.reserve_protocol_var = tk.StringVar(value="TCP")
        self.reserve_protocol_menu = ttk.OptionMenu(self.reservation_frame, self.reserve_protocol_var, "TCP", "TCP", "UDP")
        self.reserve_protocol_menu.pack(side=tk.LEFT, padx=5)
        
        self.exe_path_var = tk.StringVar()
        self.exe_path_entry = ttk.Entry(self.reservation_frame, textvariable=self.exe_path_var, width=20)
        self.exe_path_entry.pack(side=tk.LEFT, padx=5)
        
        self.browse_exe_btn = ttk.Button(self.reservation_frame, text="Browse", command=self.browse_exe, bootstyle=INFO)
        self.browse_exe_btn.pack(side=tk.LEFT, padx=5)
        
        self.reserve_btn = ttk.Button(self.reservation_frame, text="Reserve Port", command=self.reserve_port_wrapper, bootstyle=SUCCESS)
        self.reserve_btn.pack(side=tk.LEFT, padx=5)
        
        self.release_btn = ttk.Button(self.reservation_frame, text="Release Port", command=self.release_port_wrapper, bootstyle=DANGER)
        self.release_btn.pack(side=tk.LEFT, padx=5)
        
        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=tk.YES)
        
        self.scrollbar = ttk.Scrollbar(self.tree_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=('Proto', 'Local Address', 'Foreign Address', 'State', 'PID', 'Process Name'), show='headings', yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.tree.yview)
        
        columns = {'Proto': 80, 'Local Address': 200, 'Foreign Address': 200, 'State': 120, 'PID': 80, 'Process Name': 200}
        for col, width in columns.items():
            self.tree.column(col, width=width, anchor=tk.CENTER)
            self.tree.heading(col, text=col)
        self.tree.pack(fill=tk.BOTH, expand=tk.YES)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))

    def check_specific_port_wrapper(self):
        """Wrapper to validate and pass port from GUI entry to check_specific_port"""
        try:
            port = int(self.port_entry.get())
            if not (0 < port <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            self.check_specific_port(port)
        except ValueError as e:
            self.status_var.set(f"Invalid port: {str(e)}")
            messagebox.showerror("Error", f"Invalid port: {str(e)}")

    def check_specific_port(self, port):
        """Check status of a specific port"""
        connections = self.app.get_all_connections()
        found = [conn for conn in connections if conn['port'] == port]
        
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        for conn in connections:
            if conn['port'] == port:
                self.tree.insert('', tk.END, values=(
                    conn['protocol'],
                    f"{conn['local_address']}:{conn['port']}",
                    f"{conn['remote_address']}:{conn['remote_port']}" if conn['remote_address'] else '*:*',
                    conn['status'],
                    conn['pid'],
                    conn['name']
                ))
        self.status_var.set(f"Found port {port} in listed connections" if found else f"Port {port} not found in active connections")

    def browse_exe(self):
        """Open file dialog to select an executable"""
        file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe"), ("All files", "*.*")])
        if file_path:
            self.exe_path_var.set(file_path)

    def refresh_ports(self):
        """Scan and display all TCP/UDP connections"""
        self.status_var.set("Scanning all network connections...")
        self.root.update()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        connections = self.app.get_all_connections()
        for conn in connections:
            self.tree.insert('', tk.END, values=(
                conn['protocol'],
                f"{conn['local_address']}:{conn['port']}",
                f"{conn['remote_address']}:{conn['remote_port']}" if conn['remote_address'] else '*:*',
                conn['status'],
                conn['pid'],
                conn['name']
            ))
        self.status_var.set(f"Found {len(connections)} connections. Updated: {self.app.get_current_time()}")

    def save_to_file(self):
        """Save all connection data to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save connections to file"
        )
        if filename:
            success, message = self.app.save_to_file(filename)
            if success:
                messagebox.showinfo("Save Complete", message)
            else:
                messagebox.showerror("Save Error", message)

    def show_netstat_output(self):
        """Display netstat-like output in a new window"""
        output_window = ttkb.Toplevel(self.root)
        output_window.title("Netstat-Style Output")
        output_window.geometry("800x600")
        text_area = scrolledtext.ScrolledText(output_window, wrap=tk.WORD, font=('Courier', 10))
        text_area.pack(fill=tk.BOTH, expand=tk.YES, padx=10, pady=10)
        connections = self.app.get_all_connections()
        output = f"Active Connections - {self.app.get_current_time()}\n\n"
        output += "  Proto  Local Address          Foreign Address        State           PID\n"
        output += "="*80 + "\n"
        for conn in connections:
            output += (f"  {conn['protocol']:<6} {conn['local_address']}:{conn['port']:<16} "
                       f"{conn['remote_address']}:{conn['remote_port'] if conn['remote_address'] else '*':<16} "
                       f"{conn['status']:<15} {conn['pid']} ({conn['name']})\n")
        text_area.insert(tk.END, output)
        text_area.config(state='disabled')

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            values = self.tree.item(item, 'values')
            pid = values[4]
            protocol = values[0]
            port = int(values[1].split(':')[-1])
            menu = Menu(self.tree, tearoff=0)
            if pid != 'N/A':
                menu.add_command(label=f"Kill Process {pid} ({values[5]})", command=lambda: self.kill_process_wrapper(pid))
            menu.add_command(label=f"Block Connection (Port {port}, {protocol})", command=lambda: self.block_connection_wrapper(port, protocol))
            menu.add_command(label=f"Unblock Connection (Port {port}, {protocol})", command=lambda: self.unblock_connection_wrapper(port, protocol))
            menu.add_command(label=f"Open Port {port} ({protocol})", command=lambda: self.start_server_wrapper(port=port, protocol=protocol))
            menu.add_command(label=f"Reserve Port {port} ({protocol})", command=lambda: self.reserve_port_wrapper(port=port, protocol=protocol))
            menu.post(event.x_root, event.y_root)

    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if self.app.monitoring:
            self.app.monitoring = False
            self.monitor_btn.configure(text="Start Monitoring", bootstyle=SECONDARY)
            self.status_var.set("Real-time monitoring stopped")
        else:
            self.app.monitoring = True
            self.monitor_btn.configure(text="Stop Monitoring", bootstyle=DANGER)
            self.start_monitoring()

    def start_monitoring(self):
        """Periodically refresh connections"""
        if self.app.monitoring:
            self.refresh_ports()
            self.root.after(self.app.monitor_interval, self.start_monitoring)

    def kill_process_wrapper(self, pid):
        """Wrapper for kill process with confirmation"""
        if not messagebox.askyesno("Confirm", f"Are you sure you want to terminate process {pid}?"):
            return
        success, message = self.app.kill_process(pid)
        self.status_var.set(message)
        self.refresh_ports()

    def block_connection_wrapper(self, port, protocol):
        """Wrapper for block connection with confirmation"""
        if not messagebox.askyesno("Confirm", f"Block {protocol} port {port} in Windows Firewall?"):
            return
        success, message = self.app.block_connection(port, protocol)
        self.status_var.set(message)
        self.refresh_ports()

    def unblock_connection_wrapper(self, port, protocol):
        """Wrapper for unblock connection with confirmation"""
        if not messagebox.askyesno("Confirm", f"Unblock {protocol} port {port} in Windows Firewall?"):
            return
        success, message = self.app.unblock_connection(port, protocol)
        self.status_var.set(message)
        self.refresh_ports()

    def start_server_wrapper(self, port=None, protocol=None):
        """Wrapper for start server with validation"""
        if port is None:
            try:
                port = int(self.server_port_entry.get())
                protocol = self.protocol_var.get()
            except ValueError:
                self.status_var.set("Invalid port number")
                return
        
        if not (0 < port <= 65535):
            self.status_var.set("Port must be between 1 and 65535")
            return
        
        if not messagebox.askyesno("Confirm", f"Start {protocol} server on port {port}?"):
            return
            
        success, message = self.app.start_server(port, protocol)
        if success:
            self.start_server_btn.configure(state=tk.DISABLED)
            self.stop_server_btn.configure(state=tk.NORMAL)
        self.status_var.set(message)
        self.refresh_ports()

    def stop_server_wrapper(self):
        """Wrapper for stop server with confirmation"""
        if not messagebox.askyesno("Confirm", f"Stop {self.app.server_protocol} server on port {self.app.server_port}?"):
            return
        success, message = self.app.stop_server()
        if success:
            self.start_server_btn.configure(state=tk.NORMAL)
            self.stop_server_btn.configure(state=tk.DISABLED)
        self.status_var.set(message)
        self.refresh_ports()

    def reserve_port_wrapper(self, port=None, protocol=None):
        """Wrapper for reserve port with validation"""
        if port is None:
            try:
                port = int(self.reserve_port_entry.get())
                protocol = self.reserve_protocol_var.get()
                exe_path = self.exe_path_var.get() or None
            except ValueError:
                self.status_var.set("Invalid port number")
                return
        
        if not (0 < port <= 65535):
            self.status_var.set("Port must be between 1 and 65535")
            return
            
        if not messagebox.askyesno("Confirm", f"Reserve {protocol} port {port} {'for ' + exe_path if exe_path else ''}?"):
            return
            
        success, message = self.app.reserve_port(port, protocol, exe_path)
        self.status_var.set(message)
        self.refresh_ports()

    def release_port_wrapper(self):
        """Wrapper for release port with validation"""
        try:
            port = int(self.reserve_port_entry.get())
        except ValueError:
            self.status_var.set("Invalid port number")
            return
            
        if not messagebox.askyesno("Confirm", f"Release port {port}?"):
            return
            
        success, message = self.app.release_port(port)
        self.status_var.set(message)
        self.refresh_ports()

def main():
    root = ttkb.Window(themename="darkly")
    app = PortManagerGUI(root)
    root.title("Netstat Clone - Enhanced Port Manager")
    root.geometry("1000x650")
    root.mainloop()

if __name__ == "__main__":
    main()