from monitor import Monitor
import hashlib
import psutil
import os

class ProcessMonitor(Monitor):
    def __init__(self, osint_queue, db_lock, db_path, expiration):
        super().__init__(osint_queue, db_lock, db_path, expiration)
        self.create_process_table()

    def create_process_table(self):
        create_sql = '''
            CREATE TABLE IF NOT EXISTS known_processes (
                sha256_hash TEXT PRIMARY KEY,
                process_name TEXT,
                last_check TIMESTAMP,
                positives INTEGER DEFAULT 0,
                tags TEXT
            )
        '''
        self.create_table(create_sql)

    def is_process_known(self, sha256_hash):
        query_sql = '''
            SELECT 1 FROM known_processes 
            WHERE sha256_hash = ? AND last_check > ?
        '''
        return self.is_known(query_sql, sha256_hash)

    def run(self):
        """Monitor running processes and analyze them using OSINT."""
        while not self.stop_event.is_set():
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe_path = proc.info['exe']
                    process_name = proc.info['name']

                    if exe_path and os.path.isfile(exe_path):
                        with open(exe_path, 'rb') as f:
                            process_binary = f.read()
                            sha256_hash = hashlib.sha256(process_binary).hexdigest()

                        if sha256_hash not in self.local_cache and not self.is_process_known(sha256_hash):
                            self.local_cache.add(sha256_hash)
                            # Send the SHA256 hash and process name to the OSINT queue
                            self.osint_queue.put((sha256_hash, process_name))

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
                    pass

            self.stop_event.wait(1)
        self.cleanup()

    def stop_monitoring(self):
        super().stop_monitoring()

    def cleanup(self):
        super().cleanup()
        print("[*] Stopping process monitoring.")