import socket
import threading
import time

class ServerManager:
    def __init__(self):
        self.server_socket = None
        self.server_thread = None
        self.server_running = False
        self.server_port = None
        self.server_protocol = None

    def start_server(self, port, protocol):
        if self.server_running:
            return False, "Server already running"

        try:
            sock_type = socket.SOCK_STREAM if protocol == 'TCP' else socket.SOCK_DGRAM
            self.server_socket = socket.socket(socket.AF_INET, sock_type)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', port))
            
            if protocol == 'TCP':
                self.server_socket.listen(5)
                
            self.server_running = True
            self.server_port = port
            self.server_protocol = protocol
            
            # Start a thread to keep the socket alive
            def run_server():
                while self.server_running:
                    if protocol == 'TCP':
                        try:
                            conn, addr = self.server_socket.accept()
                            conn.close()
                        except:
                            pass
                    time.sleep(0.1)
            
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()
            return True, f"Server started on port {port}"
        except socket.error as e:
            return False, f"Failed to start server: {str(e)}"

    def stop_server(self):
        if not self.server_running:
            return False, "No server running"
        
        try:
            self.server_running = False
            if self.server_socket:
                self.server_socket.close()
            if self.server_thread:
                self.server_thread.join(timeout=1)
            self.server_socket = None
            self.server_thread = None
            self.server_port = None
            self.server_protocol = None
            return True, "Server stopped"
        except socket.error as e:
            return False, f"Failed to stop server: {str(e)}"

def test_server_lifecycle():
    """Test starting and stopping a server"""
    manager = ServerManager()
    
    # Test with TCP
    port = 8082
    protocol = 'TCP'
    
    # Test start
    success, message = manager.start_server(port, protocol)
    assert success, f"Start server failed: {message}"
    assert manager.server_running, "Server not marked as running"
    assert manager.server_port == port, "Incorrect port recorded"
    assert manager.server_protocol == protocol, "Incorrect protocol recorded"
    
    # Verify port is bound
    time.sleep(0.5)  # Give time for socket to bind
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.bind(('127.0.0.1', port))
        test_socket.close()
        print("ERROR: Port was available when it should be in use")
        return "FAIL", "Port was available when it should be in use"
    except socket.error:
        pass  # Expected - port should be in use
    
    # Test stop
    success, message = manager.stop_server()
    assert success, f"Stop server failed: {message}"
    assert not manager.server_running, "Server still marked as running"
    
    # Verify port is released
    time.sleep(0.5)  # Give time for socket to close
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.bind(('127.0.0.1', port))
        test_socket.close()
    except socket.error:
        print("ERROR: Port still in use after server stopped")
        return "FAIL", "Port still in use after server stopped"
    
    return "PASS", "Server lifecycle test passed"

if __name__ == "__main__":
    status, message = test_server_lifecycle()
    print(f"{status}: {message}")