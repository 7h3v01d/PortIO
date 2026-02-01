import socket
import json
import os
import time
import random
import threading
import tempfile
from contextlib import contextmanager

class PortReservationManager:
    def __init__(self):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_file = os.path.join(self.script_dir, "port_reservations.json")
        self.reserved_ports = {}
        self.active_sockets = {}
        self.lock = threading.Lock()
        self.stop_events = {}
        self.load_reservations()

    def load_reservations(self):
        print("Loading reservations...")
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        self.reserved_ports = json.loads(content)
                        print(f"Loaded reservations: {self.reserved_ports}")
                    else:
                        print("Config file is empty")
            else:
                print("Config file does not exist")
        except Exception as e:
            print(f"Failed to load reservations: {str(e)}")
            self.reserved_ports = {}

    def save_reservations(self):
        print("Saving reservations...")
        try:
            save_data = {port: {'protocol': info['protocol']} 
                        for port, info in self.reserved_ports.items()}
            print(f"Attempting to save: {save_data}")
            # Use a temporary file to avoid file locking issues
            temp_file = os.path.join(self.script_dir, f"temp_port_reservations_{os.getpid()}.json")
            with open(temp_file, 'w') as f:
                json.dump(save_data, f, indent=4)
            # Rename to final file
            os.replace(temp_file, self.config_file)
            print(f"Saved reservations to {self.config_file}")
        except (PermissionError, OSError) as e:
            print(f"Failed to save reservations due to file error: {str(e)}")
            raise
        except Exception as e:
            print(f"Failed to save reservations: {str(e)}")
            raise

    @contextmanager
    def _test_socket(self):
        """Context manager for test sockets"""
        print("Creating test socket...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            yield s
        finally:
            s.close()
            print("Closed test socket")

    def is_port_available(self, port):
        """Check if port is available"""
        print(f"Checking if port {port} is available...")
        with self._test_socket() as s:
            try:
                s.bind(('127.0.0.1', port))
                print(f"Port {port} is available")
                return True
            except socket.error as e:
                print(f"Port {port} is not available: {str(e)}")
                return False

    def find_available_port(self, start=8000, end=8999, max_attempts=50):
        """Find an available port quickly"""
        print(f"Finding available port between {start} and {end}...")
        for _ in range(max_attempts):
            port = random.randint(start, end)
            if self.is_port_available(port) and str(port) not in self.reserved_ports:
                print(f"Found available port: {port}")
                return port
        raise RuntimeError(f"No available port found after {max_attempts} attempts")

    def _keep_port_bound(self, sock, port, protocol, stop_event):
        """Thread function to maintain port binding with timeout"""
        print(f"Starting _keep_port_bound for port {port} ({protocol})...")
        try:
            with self.lock:
                self.active_sockets[port] = sock
            print(f"Registered socket for port {port}")
            try:
                sock.getsockname()
                print(f"Socket confirmed bound in _keep_port_bound on port {port}")
            except Exception as e:
                print(f"Socket not bound in _keep_port_bound on port {port}: {str(e)}")
                raise
            if protocol == 'TCP':
                while not stop_event.is_set():
                    try:
                        conn, addr = sock.accept()
                        print(f"Accepted connection from {addr} on port {port}")
                        conn.close()
                        print(f"Closed connection on port {port}")
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"Error in _keep_port_bound for TCP port {port}: {str(e)}")
                        break
            else:  # UDP
                while not stop_event.is_set():
                    time.sleep(0.5)
        except Exception as e:
            print(f"Error in _keep_port_bound for port {port}: {str(e)}")
        finally:
            with self.lock:
                if port in self.active_sockets:
                    try:
                        self.active_sockets[port].close()
                        print(f"Closed socket for port {port} in _keep_port_bound")
                    except Exception as e:
                        print(f"Error closing socket for port {port}: {str(e)}")
                    del self.active_sockets[port]

    def reserve_port(self, port, protocol):
        port = int(port)
        print(f"Reserving port {port} for {protocol}...")
        with self.lock:
            if str(port) in self.reserved_ports:
                print(f"Port {port} already reserved")
                return False, f"Port {port} is already reserved"

        if not self.is_port_available(port):
            print(f"Port {port} is in use")
            return False, f"Port {port} is currently in use"

        sock = None
        try:
            print(f"Creating socket for port {port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM)
            print(f"Binding socket for port {port} in main thread...")
            sock.bind(('127.0.0.1', port))
            if protocol == 'TCP':
                sock.listen(5)
                sock.settimeout(0.5)
                print(f"Socket listening on TCP port {port}")
            print(f"Socket bound for port {port}")

            try:
                sock.getsockname()
                print(f"Socket confirmed bound on port {port}")
            except Exception as e:
                print(f"Socket not bound on port {port}: {str(e)}")
                sock.close()
                return False, f"Failed to bind port {port}: {str(e)}"

            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._keep_port_bound,
                args=(sock, port, protocol, stop_event),
                daemon=True
            )
            thread.start()
            print(f"Started thread for port {port}")

            for attempt in range(7):
                print(f"Verifying port {port} binding (attempt {attempt + 1})...")
                time.sleep(0.5)
                if not self.is_port_available(port):
                    break
            else:
                print(f"Verification failed: port {port} is still available after retries")
                stop_event.set()
                thread.join(timeout=0.5)
                sock.close()
                return False, f"Failed to actually bind port {port}"

            with self.lock:
                self.reserved_ports[str(port)] = {
                    'protocol': protocol,
                    'thread': thread,
                    'stop_event': stop_event,
                    'socket': sock
                }
                self.save_reservations()

            print(f"Successfully reserved port {port}")
            return True, f"Reserved {protocol} port {port}"
        except Exception as e:
            print(f"Exception in reserve_port for port {port}: {str(e)}")
            if sock is not None:
                try:
                    sock.close()
                    print(f"Closed socket for port {port} due to error")
                except Exception as close_e:
                    print(f"Error closing socket for port {port}: {str(close_e)}")
            return False, f"Failed to reserve port: {str(e)}"

    def release_port(self, port):
        port = int(port)
        print(f"Releasing port {port}...")
        with self.lock:
            if str(port) not in self.reserved_ports:
                print(f"Port {port} is not reserved")
                return False, f"Port {port} is not reserved"

            try:
                info = self.reserved_ports[str(port)]
                if 'stop_event' in info:
                    info['stop_event'].set()
                    print(f"Signaled stop for port {port}")
                
                if 'thread' in info:
                    info['thread'].join(timeout=0.5)
                    print(f"Thread joined for port {port}")

                if 'socket' in info:
                    try:
                        info['socket'].close()
                        print(f"Closed socket for port {port} in release_port")
                    except Exception as e:
                        print(f"Error closing socket for port {port}: {str(e)}")

                if port in self.active_sockets:
                    try:
                        self.active_sockets[port].close()
                        print(f"Closed socket for port {port} in release_port (active_sockets)")
                    except Exception as e:
                        print(f"Error closing socket for port {port}: {str(e)}")
                    del self.active_sockets[port]

                del self.reserved_ports[str(port)]
                self.save_reservations()
                print(f"Successfully released port {port}")

                time.sleep(0.5)
                if not self.is_port_available(port):
                    print(f"Verification failed: port {port} still in use")
                    return False, f"Port {port} still in use after release"

                return True, f"Released port {port}"
            except Exception as e:
                print(f"Exception in release_port: {str(e)}")
                return False, f"Failed to release port: {str(e)}"

def test_port_reservation():
    """Test reserving and releasing a port"""
    print("Starting port reservation test...")
    config_file = os.path.join(os.path.dirname(__file__), "port_reservations.json")
    if os.path.exists(config_file):
        try:
            os.remove(config_file)
            print("Removed existing config file")
        except Exception as e:
            print(f"Failed to remove config file: {str(e)}")

    manager = PortReservationManager()

    try:
        port = manager.find_available_port()
        print(f"Testing with port {port}")
    except RuntimeError as e:
        print(f"ERROR: {str(e)}")
        return "FAIL", str(e)

    protocol = 'TCP'

    start_time = time.time()
    success, message = manager.reserve_port(port, protocol)
    if not success:
        print(f"ERROR: Reserve failed - {message}")
        return "FAIL", message

    for attempt in range(3):
        print(f"Checking if port {port} is bound (attempt {attempt + 1})...")
        time.sleep(0.2)
        if not manager.is_port_available(port):
            break
    else:
        print("ERROR: Port was available when it should be reserved")
        manager.release_port(port)
        return "FAIL", "Port was available when it should be reserved"

    success, message = manager.release_port(port)
    if not success:
        print(f"ERROR: Release failed - {message}")
        return "FAIL", message

    for attempt in range(3):
        print(f"Checking if port {port} is released (attempt {attempt + 1})...")
        time.sleep(0.2)
        if manager.is_port_available(port):
            break
    else:
        print("ERROR: Port still in use after release")
        return "FAIL", "Port still in use after release"

    print(f"Test completed in {time.time() - start_time:.2f} seconds")
    return "PASS", f"Port reservation test passed with port {port}"

if __name__ == "__main__":
    def run_with_timeout():
        status, message = test_port_reservation()
        print(f"{status}: {message}")

    test_thread = threading.Thread(target=run_with_timeout, daemon=True)
    test_thread.start()
    test_thread.join(timeout=10)  # Increased timeout

    if test_thread.is_alive():
        print("FAIL: Test timed out after 10 seconds")