from scapy.all import sniff, DNS, DNSQR, conf
from monitor import Monitor
import psutil
import time


class DNSMonitor(Monitor):  # Inherit from threading.Thread
    def __init__(self, print_lock, osint_queue, db_lock, db_path, interface=None, interface_manual=False, expiration=15):
        super().__init__(print_lock, osint_queue, db_lock, db_path, expiration)
        self.interface = interface
        self.interface_manual = interface_manual
        self.create_domain_table()

        # Choose the interface based on manual or automatic selection
        if self.interface is None:
            if self.interface_manual:
                with self.print_lock:
                    self.interface = self.choose_interface_manual()
            else:
                with self.print_lock:
                    self.interface = self.choose_interface_auto()
                
    def create_domain_table(self):
        create_sql = '''
            CREATE TABLE IF NOT EXISTS known_domains (
                domain TEXT PRIMARY KEY,
                last_check TIMESTAMP,
                positives INTEGER DEFAULT 0,
                tags TEXT
            )
        '''
        self.create_table(create_sql)

    def is_domain_known(self, domain):
        query_sql = '''
            SELECT 1 FROM known_domains 
            WHERE domain = ? AND last_check > ?
        '''
        return self.is_known(query_sql, domain)
        
    def choose_interface_manual(self):
        interfaces = list(conf.ifaces.values())
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i}: {iface.name} ({iface.description})")

        while True:
            choice = input("Enter the number of the interface you want to use: ")
            try:
                chosen_interface = interfaces[int(choice)]
                return chosen_interface.name
            except (ValueError, IndexError):
                print("Invalid choice. Please try again.")

    def choose_interface_auto(self, duration=2):
        """Automatically choose the most relevant network interface based on packet activity."""
        # Get initial packet counts for all interfaces
        initial_counts = psutil.net_io_counters(pernic=True)
        time.sleep(duration)

        # Get packet counts again after the duration
        final_counts = psutil.net_io_counters(pernic=True)

        # Calculate the difference in packet counts for each interface
        interface_activity = {}
        for iface in initial_counts:
            if iface in final_counts:
                initial = initial_counts[iface]
                final = final_counts[iface]
                # Calculate the total packets (sent + received) during the period
                packets_diff = (final.packets_sent + final.packets_recv) - (initial.packets_sent + initial.packets_recv)
                interface_activity[iface] = packets_diff

        # Choose the interface with the highest packet count difference
        most_active_interface = max(interface_activity, key=interface_activity.get)
        print(f"Automatically selected the most active interface: {most_active_interface} ({interface_activity[most_active_interface]} packets)")

        return most_active_interface
    
    def process_packet(self, packet):
        if DNS in packet and packet[DNS].qr == 0:  # DNS query
            query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.').replace('www.', '').lower()
            if query_name not in self.local_cache and not self.is_domain_known(query_name):
                with self.print_lock:
                    print(f"Checking domain: {query_name}")
                self.local_cache.add(query_name)
                self.osint_queue.put((query_name,None))

    def run(self):  # Overriding the run method to implement the thread's behavior
        with self.print_lock:
            print(f"Starting DNS monitoring on interface {self.interface}...")

        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=self.interface,
                    filter="udp port 53",  # Filter only DNS
                    prn=self.process_packet,
                    store=False,  # Prevent storing packets in memory
                    timeout=10,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
        except Exception as e:
            with self.print_lock:
                print(f"Error during packet capture: {e}")
        finally:
            self.cleanup()

    def stop_monitoring(self):
        super().stop_monitoring()

    def cleanup(self):
        super().cleanup()
        print("[*] Stopping DNS monitoring.")
