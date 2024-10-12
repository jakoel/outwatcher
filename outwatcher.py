import threading
import time
import argparse
from queue import Queue
from ip_monitor import IPMonitor
from dns_monitor import DNSMonitor
from process_monitor import ProcessMonitor
from osint import OSINT
from osint import get_api_key

# OSINT queue
osint_queue = Queue()

# Database paths
domain_db_path = 'domains.db'
ip_db_path = 'ips.db'
process_db_path = 'processes.db'

# Create a shared print lock to synchronize printing
print_lock = threading.Lock()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Processes, Network and DNS Monitoring Tool with OSINT")

    # Flags for different monitors
    parser.add_argument('--dns', action='store_true', help='Run the DNS monitor')
    parser.add_argument('--ip', action='store_true', help='Run the IP monitor')
    parser.add_argument('--process', action='store_true', help='Run the Process monitor')

    # Debug flag
    parser.add_argument('--debug', action='store_true', help='Enable debug mode for more detailed output')

    # VirusTotal and OTX key file arguments
    parser.add_argument('--vt-key', type=str, help='Path to the VirusTotal API key file', default='vt.key')
    parser.add_argument('--otx-key', type=str, help='Path to the OTX API key file', default='otx.key')
    
    parser.add_argument('--expire', type=int, help='Path to the OTX API key file', default=30)
    
    # Manual interface selection flag
    parser.add_argument('--interface_manual', action='store_true', help='Enable manual selection of network interface', default=False)

    args = parser.parse_args()

    return args

def main():
    args = parse_arguments()

    # Load the API keys from the specified or default files
    vt_key = get_api_key(args.vt_key)
    otx_key = get_api_key(args.otx_key)

    if not vt_key:
        print("No valid VirusTotal API key found. Exiting...")
        return
    if not otx_key:
        print("No valid OTX API key found. Exiting...")
        return
    
    # Create instances of the monitor and interceptor with a shared print lock
    ip_monitor = None
    dns_monitor = None
    process_monitor = None
    
    ip_db_lock = threading.Lock()
    domain_db_lock = threading.Lock()
    process_db_lock = threading.Lock()
    
    if args.ip:
        ip_monitor = IPMonitor(print_lock=print_lock, osint_queue=osint_queue, db_path=ip_db_path, db_lock=ip_db_lock,expiration=args.expire)
    if args.dns:
        dns_monitor = DNSMonitor(print_lock=print_lock, osint_queue=osint_queue, db_path=domain_db_path, db_lock=domain_db_lock, interface_manual=args.interface_manual, expiration=args.expire)
    if args.process:
        process_monitor = ProcessMonitor(print_lock=print_lock, osint_queue=osint_queue, db_lock=process_db_lock, db_path=process_db_path, expiration=args.expire)


    # Start monitoring directly as threads
    if ip_monitor:
        ip_monitor.start()
    if dns_monitor:
        dns_monitor.start()
    if process_monitor:
        process_monitor.start()
        
    osint_handler = OSINT(print_lock,vt_key, otx_key, domain_db_path, ip_db_path, process_db_path,domain_db_lock, ip_db_lock,process_db_lock)

    try:
        while True:
            # Check the OSINT queue for new data
            try:
                data = osint_queue.get(timeout=1)
                osint_handler.check_virus_total(data)
                #osint_handler.check_otx(data[0])
            except:
                pass  # Continue looping if no data is available

            time.sleep(1)

    except KeyboardInterrupt:
        print("Stopping...")

    # Stop monitoring on exit
    if ip_monitor:
        ip_monitor.stop_monitoring()
    if dns_monitor:
        dns_monitor.stop_monitoring()
    if process_monitor:
        process_monitor.stop_monitoring()
        
    if ip_monitor:
        ip_monitor.join()
    if dns_monitor:
        dns_monitor.join()
    if process_monitor:
        process_monitor.join()

if __name__ == "__main__":
    main()