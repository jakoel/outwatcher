from monitor import Monitor
import psutil
import time

import ipaddress

class IPMonitor(Monitor):
    def __init__(self, print_lock, osint_queue, db_lock, db_path, expiration=15):
        super().__init__(print_lock, osint_queue, db_lock, db_path, expiration)
        self.create_ip_table()

    def create_ip_table(self):
        create_sql = '''
            CREATE TABLE IF NOT EXISTS known_ips (
                ip TEXT PRIMARY KEY,
                last_check TIMESTAMP,
                positives INTEGER DEFAULT 0,
                tags TEXT,
                process_name TEXT
            )
        '''
        self.create_table(create_sql)
            
    def is_ip_known(self, ip):
        query_sql = '''
            SELECT 1 FROM known_ips 
            WHERE ip = ? AND last_check > ?
        '''
        return self.is_known(query_sql, ip)

    def is_valid_public_ip(self, ip):
        """Check if the IP address is a valid public IP."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Return True only if the IP is not private, loopback, reserved, or multicast
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast)
        except ValueError:
            # If ipaddress throws an error, it means the IP is invalid
            return False

    def run(self):  # Use 'run' method to define the thread's behavior
        while not self.stop_event.is_set():
            for conn in psutil.net_connections(kind='inet'):
                if self.stop_event.is_set():
                    break  # Exit immediately if stop_event is set
                
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    # Check if the remote IP is a valid public IP
                    if not self.is_valid_public_ip(conn.raddr.ip):
                        continue  # Skip loopback, private, or invalid IPs

                    if conn.raddr.ip not in self.local_cache:
                        process_name = psutil.Process(conn.pid).name() if conn.pid else None
                        self.local_cache.add(conn.raddr.ip)
                        connection_data = {
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'remote_ip': conn.raddr.ip,
                            'remote_port': conn.raddr.port,
                            'pid': conn.pid,
                            'process': process_name
                        }

                        # Check if the remote IP is in the local cache or the database
                        if  not self.is_ip_known(connection_data['remote_ip']):
                            # Add unknown IP to the local cache and OSINT queue
                            with self.print_lock:
                                print(f"Checking IP: {connection_data['remote_ip']}, Process: {process_name}")
                                #print(self.local_cache)
                            self.local_cache.add(connection_data['remote_ip'])
                            self.osint_queue.put((connection_data['remote_ip'], process_name))

            time.sleep(1)  # Wait 1 second before checking again
            
        self.cleanup()

    def stop_monitoring(self):
        super().stop_monitoring()

    def cleanup(self):
        super().cleanup()
        print("[*] Stopping IP monitoring.")

