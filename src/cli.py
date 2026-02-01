import argparse
from core import PortManager

def main():
    parser = argparse.ArgumentParser(description="Portmaster: A network port management tool")
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List command
    subparsers.add_parser('list', help='List all active connections')
    
    # Check-port command (updated with proper validation)
    check_parser = subparsers.add_parser('check-port', help='Check if a specific port is in use')
    check_parser.add_argument('port', type=int, help='Port number to check')
    
    # Kill command
    kill_parser = subparsers.add_parser('kill', help='Kill a process by PID')
    kill_parser.add_argument('pid', type=int, help='PID of the process to kill')
    
    # Block command
    block_parser = subparsers.add_parser('block', help='Block a port with a firewall rule')
    block_parser.add_argument('port', type=int, help='Port number to block')
    block_parser.add_argument('protocol', choices=['TCP', 'UDP'], help='Protocol (TCP or UDP)')
    
    # Unblock command
    unblock_parser = subparsers.add_parser('unblock', help='Unblock a port by removing firewall rule')
    unblock_parser.add_argument('port', type=int, help='Port number to unblock')
    unblock_parser.add_argument('protocol', choices=['TCP', 'UDP'], help='Protocol (TCP or UDP)')
    
    # Start-server command
    start_server_parser = subparsers.add_parser('start-server', help='Start a server on a port')
    start_server_parser.add_argument('port', type=int, help='Port number to start server on')
    start_server_parser.add_argument('protocol', choices=['TCP', 'UDP'], help='Protocol (TCP or UDP)')
    
    # Stop-server command
    stop_server_parser = subparsers.add_parser('stop-server', help='Stop the running server')
    
    # Reserve command
    reserve_parser = subparsers.add_parser('reserve', help='Reserve a port')
    reserve_parser.add_argument('port', type=int, help='Port number to reserve')
    reserve_parser.add_argument('protocol', choices=['TCP', 'UDP'], help='Protocol (TCP or UDP)')
    reserve_parser.add_argument('--exe-path', help='Path to executable for firewall rule', default=None)
    
    # Release command
    release_parser = subparsers.add_parser('release', help='Release a reserved port')
    release_parser.add_argument('port', type=int, help='Port number to release')
    
    # Save command
    save_parser = subparsers.add_parser('save', help='Save connections to a file')
    save_parser.add_argument('filename', help='Output filename')
    
    args = parser.parse_args()
    
    if not args.command:
        print("No command specified. Use -h for help.")
        return
    
    app = PortManager()
    
    if args.command == 'list':
        connections = app.get_all_connections()
        for conn in connections:
            print(f"{conn['protocol']} {conn['local_address']}:{conn['port']} {conn['remote_address']}:{conn['remote_port']} {conn['status']} {conn['pid']} ({conn['name']})")
    
    elif args.command == 'check-port':
        # Added explicit port validation
        if not (0 < args.port <= 65535):
            print("Port must be between 1 and 65535")
            return
            
        connections = app.get_all_connections()
        found = [conn for conn in connections if conn['port'] == args.port]
        if found:
            for conn in found:
                print(f"{conn['protocol']} {conn['local_address']}:{conn['port']} {conn['remote_address']}:{conn['remote_port']} {conn['status']} {conn['pid']} ({conn['name']})")
        else:
            print(f"Port {args.port} not found in active connections")
    
    elif args.command == 'kill':
        success, message = app.kill_process(args.pid, cli=True)
        print(message)
    
    elif args.command == 'block':
        success, message = app.block_connection(args.port, args.protocol, cli=True)
        print(message)
    
    elif args.command == 'unblock':
        success, message = app.unblock_connection(args.port, args.protocol, cli=True)
        print(message)
    
    elif args.command == 'start-server':
        success, message = app.start_server(args.port, args.protocol, cli=True)
        print(message)
    
    elif args.command == 'stop-server':
        success, message = app.stop_server(cli=True)
        print(message)
    
    elif args.command == 'reserve':
        success, message = app.reserve_port(args.port, args.protocol, args.exe_path, cli=True)
        print(message)
    
    elif args.command == 'release':
        success, message = app.release_port(args.port, cli=True)
        print(message)
    
    elif args.command == 'save':
        success, message = app.save_to_file(args.filename)
        print(message)

if __name__ == "__main__":
    main()