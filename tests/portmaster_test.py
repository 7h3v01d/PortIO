import subprocess
import psutil
import os
import time
import json
import socket
import sys
import ctypes
import zmq
from datetime import datetime

def run_command(args, input_text=None):
    """Run a CLI command and return output"""
    # Get the directory where the test script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cli_path = os.path.join(script_dir, "cli.py")
    
    cmd = [sys.executable, cli_path] + args
    process = subprocess.run(cmd, capture_output=True, text=True, input=input_text)
    
    # Use relative path for log file
    test_log_path = os.path.join(script_dir, "test_log.txt")
    with open(test_log_path, 'a') as f:
        f.write(f"Command: {' '.join(cmd)}\n")
        f.write(f"Stdout: {process.stdout}\n")
        f.write(f"Stderr: {process.stderr}\n")
        f.write(f"Returncode: {process.returncode}\n\n")
    return process.stdout, process.stderr, process.returncode

def check_firewall_rule(rule_name):
    """Check if a firewall rule exists"""
    cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}']
    result = subprocess.run(cmd, capture_output=True, text=True)
    return "Rule Name:" in result.stdout

def is_port_bound(port):
    """Check if a port is bound"""
    time.sleep(2)  # Increased delay for reliable detection
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr and conn.laddr.port == port:
            return True
    return False

def get_all_connections():
    """Get all TCP and UDP connections (from core.py)"""
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
        print("Warning: Some connections inaccessible (run as admin for full details)")
    return connections

def find_free_port(start_port=49152, max_retries=300):
    """Find a free port in the ephemeral range with retries"""
    for attempt in range(max_retries):
        port = start_port + (attempt % (65535 - start_port + 1))
        if not any(conn['port'] == port for conn in get_all_connections()):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(('0.0.0.0', port))
                return port
            except socket.error:
                pass
        time.sleep(1)  # 1-second delay between retries
    raise RuntimeError(f"Failed to find free port after {max_retries} attempts")

def simulate_zeromq_pub_sub(pub_port, sub_port=None):
    """Simulate ZeroMQ PUB-SUB binding and connection"""
    context = zmq.Context()
    pub_socket = context.socket(zmq.PUB)
    sub_socket = context.socket(zmq.SUB)
    try:
        pub_socket.setsockopt(zmq.LINGER, 0)
        pub_socket.bind(f"tcp://*:{pub_port}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        test_log_path = os.path.join(script_dir, "test_log.txt")
        with open(test_log_path, 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Bound PUB socket to tcp://*:{pub_port}\n")
        
        sub_port = sub_port or pub_port  # Use same port for SUB unless specified
        sub_socket.setsockopt(zmq.SUBSCRIBE, b"")
        sub_socket.setsockopt(zmq.LINGER, 0)
        sub_socket.connect(f"tcp://localhost:{sub_port}")
        with open(test_log_path, 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Connected SUB socket to tcp://localhost:{sub_port}\n")
        
        # Send and receive a test message
        time.sleep(0.2)  # Increased delay for connection stability
        pub_socket.send(b"Test message")
        poller = zmq.Poller()
        poller.register(sub_socket, zmq.POLLIN)
        events = dict(poller.poll(2000))  # Increased timeout to 2 seconds
        if sub_socket in events and events[sub_socket] == zmq.POLLIN:
            message = sub_socket.recv()
            with open(test_log_path, 'a') as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Received message: {message.decode()}\n")
            assert message == b"Test message", "Failed to receive correct message"
        else:
            raise RuntimeError("Failed to receive message")
    finally:
        pub_socket.close()
        sub_socket.close()
        context.term()
        time.sleep(20)  # 20-second cleanup delay for TIME_WAIT

def cleanup():
    """Clean up test artifacts"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, "port_reservations.json")
    test_log_path = os.path.join(script_dir, "test_log.txt")
    test_output_path = os.path.join(script_dir, "test_output.txt")
    
    ports = [8081, 8082, 8083]
    protocols = ['TCP', 'UDP']
    
    # Forcibly clear port reservations
    for port in ports:
        for protocol in protocols:
            for rule_prefix in ['Block', 'Reserve']:
                rule_name = f"{rule_prefix}_{protocol}_{port}"
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'], capture_output=True)
            stdout, stderr, rc = run_command(['release', str(port)], input_text='y\n')
            with open(test_log_path, 'a') as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Attempted to release port {port}: {stdout}\n")
            # Verify port is free
            if is_port_bound(port):
                with open(test_log_path, 'a') as f:
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Port {port} still bound, attempting to free\n")
                for conn in get_all_connections():
                    if conn['port'] == port and conn['pid'] != 'N/A':
                        try:
                            psutil.Process(conn['pid']).terminate()
                            with open(test_log_path, 'a') as f:
                                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Terminated PID {conn['pid']} for port {port}\n")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
    
    # Clear port_reservations.json
    if os.path.exists(config_file):
        try:
            with open(config_file, 'w') as f:
                json.dump({}, f)
            with open(test_log_path, 'a') as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Cleared {config_file}\n")
        except Exception as e:
            with open(test_log_path, 'a') as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Failed to clear {config_file}: {str(e)}\n")
    
    if os.path.exists(test_output_path):
        os.remove(test_output_path)

def test_list_connections():
    """Test listing connections"""
    stdout, stderr, rc = run_command(['list'])
    assert rc == 0, f"List failed: {stderr}"
    assert "TCP" in stdout or "UDP" in stdout, "No connections listed"
    return "PASS", "Listed connections successfully"

def test_check_port():
    """Test checking a specific port"""
    stdout, stderr, rc = run_command(['check-port', '8080'])
    assert rc == 0, f"Check port failed: {stderr}"
    stdout, stderr, rc = run_command(['check-port', '70000'])
    assert "Port must be between 1 and 65535" in stdout, "Invalid port not handled"
    return "PASS", "Check port worked correctly"

def test_kill_process():
    """Test killing a process"""
    process = subprocess.Popen(['notepad.exe'])
    pid = process.pid
    time.sleep(1)
    stdout, stderr, rc = run_command(['kill', str(pid)], input_text='y\n')
    assert rc == 0, f"Kill process failed: {stderr}"
    assert "Terminated process" in stdout, "Process not terminated"
    assert not psutil.pid_exists(pid), "Process still running"
    stdout, stderr, rc = run_command(['kill', '0'])
    combined_output = (stdout + stderr).lower()
    assert "cannot terminate system process" in combined_output, "System process error not handled"
    return "PASS", "Kill process worked correctly"

def test_block_unblock_connection():
    """Test blocking and unblocking a port"""
    port, protocol = 8081, 'TCP'
    rule_name = f"Block_{protocol}_{port}"
    stdout, stderr, rc = run_command(['block', str(port), protocol], input_text='y\n')
    assert rc == 0, f"Block failed: {stderr}"
    assert "admin privileges required" not in stdout.lower(), "Admin privilege error"
    assert "Blocked" in stdout, "Block not confirmed"
    assert check_firewall_rule(rule_name), "Firewall rule not created"
    stdout, stderr, rc = run_command(['unblock', str(port), protocol], input_text='y\n')
    assert rc == 0, f"Unblock failed: {stderr}"
    assert "Unblocked" in stdout, "Unblock not confirmed"
    assert not check_firewall_rule(rule_name), "Firewall rule not removed"
    return "PASS", "Block/unblock worked correctly"

def test_start_stop_server():
    """Test starting and stopping a server"""
    port, protocol = 8082, 'TCP'
    stdout, stderr, rc = run_command(['start-server', str(port), protocol], input_text='y\n')
    assert rc == 0, f"Start server failed: {stderr}"
    assert "Started" in stdout, "Server not started"
    assert is_port_bound(port), f"Port {port} not bound: {stderr}"
    stdout, stderr, rc = run_command(['stop-server'], input_text='y\n')
    assert rc == 0, f"Stop server failed: {stderr}"
    assert "Server stopped" in stdout, "Server not stopped"
    assert not is_port_bound(port), "Port still bound"
    stdout, stderr, rc = run_command(['start-server', '80', protocol], input_text='y\n')
    assert "admin privileges required" in stdout.lower(), "Privileged port error not handled"
    return "PASS", "Start/stop server worked correctly"

def test_reserve_release_port():
    """Test reserving and releasing a port"""
    port, protocol, exe_path = 8083, 'TCP', r"C:\Windows\notepad.exe"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, "port_reservations.json")
    
    # Ensure port is released first
    run_command(['release', str(port)], input_text='y\n')
    
    stdout, stderr, rc = run_command(['reserve', str(port), protocol, '--exe-path', exe_path], input_text='y\n')
    assert rc == 0, f"Reserve failed: {stderr}"
    assert "Reserved" in stdout, "Port not reserved"
    assert is_port_bound(port), f"Port {port} not bound: {stderr}"
    assert check_firewall_rule(f"Reserve_{protocol}_{port}"), "Firewall rule not created"
    with open(config_file, 'r') as f:
        config = json.load(f)
    assert str(port) in config, "Port not in config file"
    
    stdout, stderr, rc = run_command(['release', str(port)], input_text='y\n')
    assert rc == 0, f"Release failed: {stderr}"
    assert "Released" in stdout, "Port not released"
    assert not is_port_bound(port), "Port still bound"
    assert not check_firewall_rule(f"Reserve_{protocol}_{port}"), "Firewall rule not removed"
    with open(config_file, 'r') as f:
        config = json.load(f)
    assert str(port) not in config, "Port still in config file"
    
    stdout, stderr, rc = run_command(['reserve', '70000', protocol], input_text='y\n')
    assert "Port must be between 1 and 65535" in stdout, "Invalid port not handled"
    return "PASS", "Reserve/release worked correctly"

def test_save_to_file():
    """Test saving connections to a file"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(script_dir, "test_output.txt")
    stdout, stderr, rc = run_command(['save', filename])
    assert rc == 0, f"Save failed: {stderr}"
    assert os.path.exists(filename), "Output file not created"
    with open(filename, 'r') as f:
        content = f.read()
    assert "Active Connections" in content, "Invalid file content"
    os.remove(filename)
    return "PASS", "Save to file worked correctly"

def test_zeromq_throughput_ports():
    """Test port requirements for test_zeromq_throughput.py"""
    port = find_free_port()
    assert 49152 <= port <= 65535, f"Port {port} not in ephemeral range"
    assert not is_port_bound(port), f"Port {port} already bound before test"
    
    try:
        simulate_zeromq_pub_sub(port)
        assert is_port_bound(port), f"Port {port} not bound during test"
    except Exception as e:
        raise AssertionError(f"ZeroMQ PUB-SUB failed: {str(e)}")
    
    time.sleep(20)  # Ensure cleanup delay
    assert not is_port_bound(port), f"Port {port} not released after cleanup"
    return "PASS", "ZeroMQ throughput port test passed"

def test_cortical_output_ports():
    """Test port requirements for test_cortical_output.py"""
    port = find_free_port()
    assert 49152 <= port <= 65535, f"Port {port} not in ephemeral range"
    assert not is_port_bound(port), f"Port {port} already bound before test"
    
    try:
        simulate_zeromq_pub_sub(port)
        assert is_port_bound(port), f"Port {port} not bound during test"
    except Exception as e:
        raise AssertionError(f"ZeroMQ PUB-SUB failed: {str(e)}")
    
    time.sleep(20)  # Ensure cleanup delay
    assert not is_port_bound(port), f"Port {port} not released after cleanup"
    return "PASS", "Cortical output port test passed"

def test_router_ports():
    """Test port requirements for test_router.py"""
    port = find_free_port()  # Single port for PUB-SUB
    assert 49152 <= port <= 65535, f"Port {port} not in ephemeral range"
    assert not is_port_bound(port), f"Port {port} already bound before test"
    
    try:
        simulate_zeromq_pub_sub(port)  # Use same port for PUB and SUB
        assert is_port_bound(port), f"Port {port} not bound during test"
    except Exception as e:
        raise AssertionError(f"ZeroMQ PUB-SUB failed: {str(e)}")
    
    time.sleep(20)  # Ensure cleanup delay
    assert not is_port_bound(port), f"Port {port} not released after cleanup"
    return "PASS", "Router port test passed"

def main():
    # Check admin privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Error: Test suite requires admin privileges for full functionality")
        sys.exit(1)
    
    # Check ZeroMQ dependency
    try:
        import zmq
    except ImportError:
        print("Error: pyzmq is required for ZeroMQ tests. Install with 'pip install pyzmq'")
        sys.exit(1)
    
    # Clean up before tests
    cleanup()
    
    # Initialize test log
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_log_path = os.path.join(script_dir, "test_log.txt")
    with open(test_log_path, 'w') as f:
        f.write(f"Test Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
    
    tests = [
        ("List Connections", test_list_connections),
        ("Check Port", test_check_port),
        ("Kill Process", test_kill_process),
        ("Block/Unblock Connection", test_block_unblock_connection),
        ("Start/Stop Server", test_start_stop_server),
        ("Reserve/Release Port", test_reserve_release_port),
        ("Save to File", test_save_to_file),
        ("ZeroMQ Throughput Ports", test_zeromq_throughput_ports),
        ("Cortical Output Ports", test_cortical_output_ports),
        ("Router Ports", test_router_ports)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            status, message = test_func()
            results.append((name, status, message))
        except AssertionError as e:
            results.append((name, "FAIL", str(e)))
        except Exception as e:
            results.append((name, "ERROR", f"Unexpected error: {str(e)}"))
    
    print("\nTest Suite Results:")
    print("="*50)
    for name, status, message in results:
        print(f"{name}: {status} - {message}")
    
    passed = sum(1 for _, status, _ in results if status == "PASS")
    print(f"\nSummary: {passed}/{len(tests)} tests passed")
    if passed == len(tests):
        print("All tests passed successfully!")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()