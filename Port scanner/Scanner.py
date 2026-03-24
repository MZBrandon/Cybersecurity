# Built in tool for networking
import socket 
# Function called scan ports 
def scan_ports(targets, start_port, end_port):
    print(f"\scanning {target} from port {start_port} to {end_port}...\n")
    open_ports = []
    # Goes through every port one by one
    for port in range(start_port, end_port + 1):
        # Create a timer where it checks the port for a half a second then moves on.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        # If result is 0 then the port answerd
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f" Port {port}: OPEN")
            open_ports.append(port)
        # Sock close is for closing the port it just opened
        sock.close()
        
    print(f"\nScan complete. {len(open_ports)} open port(s) found")
    return open_ports

target = input("Enter target IP or Hostname")
scan_ports(target, 1, 1024)
