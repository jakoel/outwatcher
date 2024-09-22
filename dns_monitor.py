from scapy.all import sniff, DNS, DNSQR, conf
from datetime import datetime, timedelta
import threading
import sqlite3
import time
import psutil

class DNSMonitor(threading.Thread):  # Inherit from threading.Thread
    def __init__(self, print_lock, osint_queue, db_lock, db_path, interface=None,interface_manual=False, expiration=15):
        super().__init__()  # Properly initialize the thread
        self.stop_event = threading.Event()
        self.print_lock = print_lock
        self.osint_queue = osint_queue
        self.db_path = db_path
        self.db_lock = db_lock
        self.conn = None
        self.local_cache = set()  # Local cache to store recently processed domains
        self.interface = interface
        self.interface_manual = interface_manual
        self.create_domain_table()
        self.expiration = expiration

        # Choose the interface based on manual or automatic selection
        if self.interface is None:
            if self.interface_manual:
                with self.print_lock:
                    self.interface = self.choose_interface_manual()
            else:
                with self.print_lock:
                    self.interface = self.choose_interface_auto()
                
    def create_domain_table(self):
        ''' Creating table if it's not already exist'''
        with self.db_lock:  # Ensure thread-safe access
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            with self.conn:
                self.conn.execute('''
                    CREATE TABLE IF NOT EXISTS known_domains (
                        domain TEXT PRIMARY KEY,
                        last_check TIMESTAMP,
                        positives INTEGER DEFAULT 0
                    )
                ''')

    def is_domain_known(self, domain):
        """Check if the domain is already known in the database and if last_checked is within the expiration period."""
        # Calculate the threshold date (expiration period)
        threshold_date = (datetime.now() - timedelta(days=self.expiration)).strftime('%Y-%m-%d %H:%M:%S')

        with self.db_lock:
            if self.conn is None:
                return False
            cursor = self.conn.cursor()

            # Query to check if the domain exists and last_check is within the expiration period
            cursor.execute("""
                SELECT 1 FROM known_domains 
                WHERE domain = ? AND last_check > ?
            """, (domain, threshold_date))

            # If the query returns a result, the domain is known and last_checked is within the expiration period
            return cursor.fetchone() is not None
        
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
        self.stop_event.set()

    def cleanup(self):
        """Cleanup resources and close database connections."""
        with self.db_lock:  # Ensure thread-safe cleanup
            if self.conn:
                self.conn.close()
        print("Stopping DNS monitoring...")
