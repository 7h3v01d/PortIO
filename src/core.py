import socket
import psutil
import json
import os
import subprocess
import ctypes
from datetime import datetime

class PortManager:
    def __init__(self):
        # Get the directory where the script is located
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Set file paths relative to script directory
        self.log_file = os.path.join(self.script_dir, "port_logs.txt")
        self.config_file = os.path.join(self.script_dir, "port_reservations.json")
        
        self.monitoring = False
        self.monitor_interval = 5000  # 5 seconds
        self.server_socket = None
        self.server_running = False
        self.server_port = None
        self.server_protocol = None
        self.reserved_ports = {}  # {port: {'protocol': str, 'exe_path': str, 'socket': socket}}
        
        # Check admin privileges
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not self.is_admin:
            self.log_message("Warning: Run as administrator for full functionality (ports <1024, firewall rules, process termination)")
        
        # Clear stale port 8083 reservation
        self.clear_stale_reservations([8083])
        
        # Load existing reservations
        self.load_reservations()

    def is_port_in_use(self, port):
        """Check if a port is in use by any process"""
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.laddr.port == port:
                return True
        return False

    def log_message(self, message):
        """Log a message to the log file"""
        with open(self.log_file, 'a') as f:
            f.write(f"{self.get_current_time()} - {message}\n")

    def clear_stale_reservations(self, ports):
        """Clear stale reservations for specified ports"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                for port in ports:
                    if str(port) in config:
                        self.release_port(port, cli=True)
                        self.log_message(f"Cleared stale reservation for port {port}")
                # Rewrite config file to remove stale entries
                with open(self.config_file, 'w') as f:
                    json.dump({k: v for k, v in config.items() if int(k) not in ports}, f, indent=4)
        except Exception as e:
            self.log_message(f"Failed to clear stale reservations: {str(e)}")

    def load_reservations(self):
        """Load reserved ports from config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.reserved_ports = json.load(f)
                self.reserved_ports = {int(k): {'protocol': v['protocol'], 'exe_path': v['exe_path'], 'socket': None} 
                                    for k, v in self.reserved_ports.items()}
                for port, info in list(self.reserved_ports.items()):
                    try:
                        self.reserve_port(port, info['protocol'], info['exe_path'], from_config=True, cli=True)
                    except Exception as e:
                        self.log_message(f"Failed to reload reservation for port {port}: {str(e)}")
                        del self.reserved_ports[port]
                        self.save_reservations()
        except Exception as e:
            self.log_message(f"Failed to load reservations: {str(e)}")

    def save_reservations(self):
        """Save reserved ports to config file"""
        try:
            config = {str(port): {'protocol': info['protocol'], 'exe_path': info['exe_path']} 
                    for port, info in self.reserved_ports.items()}
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            self.log_message(f"Failed to save reservations: {str(e)}")

    def get_current_time(self):
        """Get current time in YYYY-MM-DD HH:MM:SS format"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def get_all_connections(self):
        """Get all TCP and UDP connections with detailed information"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr:
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid is not None else None
                        name = proc.name() if proc else "System"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = "Unknown"
                    connections.append({
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'port': conn.laddr.port,
                        'status': conn.status if conn.type == socket.SOCK_STREAM else 'NONE',
                        'name': name,
                        'pid': conn.pid if conn.pid is not None else 'N/A',
                        'local_address': conn.laddr.ip if conn.laddr.ip else '0.0.0.0',
                        'remote_address': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0
                    })
        except psutil.AccessDenied:
            self.log_message("Warning: Some connections inaccessible (run as admin for full details)")
        return connections

    def is_port_available(self, port):
        """Check if a port is available for binding"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return True
            except socket.error as e:
                self.log_message(f"Port {port} binding check failed: {str(e)}")
                return False

    def kill_process(self, pid, cli=False):
        """Terminate a process by PID"""
        if pid == 0 or pid == '0':
            msg = "Cannot terminate system process"
            self.log_message(msg)
            return False, msg

        try:
            if pid != 'N/A':
                process = psutil.Process(int(pid))
                process.terminate()
                process.wait(timeout=3)  # Wait for termination
                msg = f"Terminated process {pid}"
                self.log_message(msg)
                return True, msg
            else:
                msg = "Cannot terminate system process"
                self.log_message(msg)
                return False, msg
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
            msg = f"Failed to terminate process: {str(e)}"
            self.log_message(msg)
            return False, msg

    def block_connection(self, port, protocol, cli=False):
        """Block a connection by adding a firewall rule"""
        if not self.is_admin:
            msg = "Admin privileges required to manage firewall rules"
            self.log_message(msg)
            return False, msg

        try:
            rule_name = f"Block_{protocol}_{port}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}', 'dir=in', 'action=block',
                f'protocol={protocol}', f'localport={port}'
            ], check=True)
            msg = f"Blocked {protocol} port {port}"
            self.log_message(msg)
            return True, msg
        except subprocess.CalledProcessError as e:
            msg = f"Failed to block port: {str(e)}"
            self.log_message(msg)
            return False, msg

    def unblock_connection(self, port, protocol, cli=False):
        """Unblock a connection by removing a firewall rule"""
        if not self.is_admin:
            msg = "Admin privileges required to manage firewall rules"
            self.log_message(msg)
            return False, msg

        try:
            rule_name = f"Block_{protocol}_{port}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}', f'protocol={protocol}', f'localport={port}'
            ], check=True)
            msg = f"Unblocked {protocol} port {port}"
            self.log_message(msg)
            return True, msg
        except subprocess.CalledProcessError as e:
            msg = f"Failed to unblock port: {str(e)}"
            self.log_message(msg)
            return False, msg

    def start_server(self, port, protocol, cli=False):
        """Start a TCP or UDP server on the specified port"""
        if self.server_running:
            msg = "A server is already running. Stop it first."
            self.log_message(msg)
            return False, msg

        if not (0 < port <= 65535):
            msg = "Port must be between 1 and 65535"
            self.log_message(msg)
            return False, msg

        # Check if port is already bound (including by our own reservation)
        if port in self.reserved_ports or self.is_port_in_use(port):
            msg = f"Port {port} is already in use"
            self.log_message(msg)
            return False, msg

        if port < 1024 and not self.is_admin:
            msg = "Ports below 1024 require admin privileges"
            self.log_message(msg)
            return False, msg

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setblocking(False)
            self.server_socket.bind(('0.0.0.0', port))
            if protocol == 'TCP':
                self.server_socket.listen(5)
                self.log_message(f"Bound and listening on {protocol} port {port} (state: LISTEN)")
            else:
                self.log_message(f"Bound on {protocol} port {port}")
            self.server_running = True
            self.server_port = port
            self.server_protocol = protocol
            msg = f"Started {protocol} server on port {port}"
            self.log_message(msg)
            return True, msg
        except socket.error as e:
            msg = f"Failed to start server: {str(e)}"
            self.log_message(msg)
            self.server_socket = None
            self.server_running = False
            return False, msg

    def stop_server(self, cli=False):
        """Stop the running server"""
        if not self.server_running:
            msg = "No server is running"
            self.log_message(msg)
            return False, msg

        try:
            if self.server_socket:
                self.server_socket.close()
            self.server_socket = None
            self.server_running = False
            self.server_port = None
            self.server_protocol = None
            msg = "Server stopped"
            self.log_message(msg)
            return True, msg
        except socket.error as e:
            msg = f"Failed to stop server: {str(e)}"
            self.log_message(msg)
            return False, msg

    def reserve_port(self, port, protocol, exe_path=None, from_config=False, cli=False):
        """Reserve a port by binding a socket and optionally adding a firewall rule"""
        if not (0 < port <= 65535):
            msg = "Port must be between 1 and 65535"
            self.log_message(msg)
            return False, msg

        if port in self.reserved_ports and not from_config:
            msg = f"Port {port} is already reserved"
            self.log_message(msg)
            return False, msg

        # Check if port is in use by any process (including our own server)
        if self.is_port_in_use(port) and not from_config:
            msg = f"Port {port} is already in use"
            self.log_message(msg)
            return False, msg

        if port < 1024 and not self.is_admin:
            msg = "Ports below 1024 require admin privileges"
            self.log_message(msg)
            return False, msg

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind(('0.0.0.0', port))
            self.log_message(f"Bound socket on {protocol} port {port}")
            if protocol == 'TCP':
                sock.listen(5)
                self.log_message(f"Listening on {protocol} port {port}")
            if exe_path:
                if not os.path.exists(exe_path):
                    msg = f"Executable path {exe_path} does not exist"
                    sock.close()
                    self.log_message(msg)
                    return False, msg
                try:
                    rule_name = f"Reserve_{protocol}_{port}"
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}', 'dir=in', 'action=allow',
                        f'program={exe_path}', f'protocol={protocol}', f'localport={port}'
                    ], check=True)
                    self.log_message(f"Added firewall rule for {protocol} port {port} (program: {exe_path})")
                except subprocess.CalledProcessError as e:
                    sock.close()
                    msg = f"Failed to add firewall rule: {str(e)}"
                    self.log_message(msg)
                    return False, msg
            self.reserved_ports[port] = {'protocol': protocol, 'exe_path': exe_path, 'socket': sock}
            self.save_reservations()
            msg = f"Reserved {protocol} port {port} {'for ' + exe_path if exe_path else ''}"
            self.log_message(msg)
            return True, msg
        except socket.error as e:
            msg = f"Failed to reserve port: {str(e)}"
            self.log_message(msg)
            return False, msg

    def release_port(self, port, cli=False):
        """Release a reserved port"""
        if not (0 < port <= 65535):
            msg = "Port must be between 1 and 65535"
            self.log_message(msg)
            return False, msg

        if port not in self.reserved_ports:
            msg = f"Port {port} is not reserved"
            self.log_message(msg)
            return False, msg

        try:
            if self.reserved_ports[port]['socket']:
                try:
                    self.reserved_ports[port]['socket'].close()
                    self.log_message(f"Closed socket for port {port}")
                except socket.error:
                    pass  # Socket may already be closed
            if self.reserved_ports[port]['exe_path']:
                try:
                    rule_name = f"Reserve_{self.reserved_ports[port]['protocol']}_{port}"
                    protocol = self.reserved_ports[port]['protocol']
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name={rule_name}'
                    ], check=True, capture_output=True)
                    self.log_message(f"Removed firewall rule for {protocol} port {port}")
                except subprocess.CalledProcessError as e:
                    if "No rules match" not in str(e):
                        msg = f"Failed to remove firewall rule: {str(e)}"
                        self.log_message(msg)
            del self.reserved_ports[port]
            self.save_reservations()
            msg = f"Released port {port}"
            self.log_message(msg)
            return True, msg
        except Exception as e:
            msg = f"Failed to release port: {str(e)}"
            self.log_message(msg)
            # Ensure port is removed from reservations even if errors occur
            if port in self.reserved_ports:
                del self.reserved_ports[port]
                self.save_reservations()
            return False, msg

    def save_to_file(self, filename=None):
        """Save all connection data to file in netstat-like format"""
        try:
            if filename is None:
                filename = os.path.join(self.script_dir, f"netstat_clone_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            else:
                filename = os.path.join(self.script_dir, filename)
                
            connections = self.get_all_connections()
            with open(filename, 'w') as f:
                f.write(f"Active Connections - {self.get_current_time()}\n\n")
                f.write("  Proto  Local Address          Foreign Address        State           PID\n")
                f.write("="*80 + "\n")
                for conn in connections:
                    f.write(f"  {conn['protocol']:<6} {conn['local_address']}:{conn['port']:<16} "
                            f"{conn['remote_address']}:{conn['remote_port'] if conn['remote_address'] else '*':<16} "
                            f"{conn['status']:<15} {conn['pid']} ({conn['name']})\n")
            msg = f"Saved {len(connections)} connections to {filename}"
            self.log_message(msg)
            return True, msg
        except Exception as e:
            msg = f"Failed to save connections: {str(e)}"
            self.log_message(msg)
            return False, msg