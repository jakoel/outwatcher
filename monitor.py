from abc import ABC, abstractmethod
import threading
import sqlite3
from datetime import timedelta,datetime

class Monitor(ABC, threading.Thread):
    def __init__(self, osint_queue, db_lock, db_path, expiration=15):
        super().__init__()
        self.stop_event = threading.Event()
        self.osint_queue = osint_queue
        self.db_lock = db_lock
        self.db_path = db_path
        self.expiration = expiration
        self.conn = None
        self.local_cache = set()

    @abstractmethod
    def run(self):
        """Abstract method that must be implemented by the subclasses to monitor entities."""
        pass

    def stop_monitoring(self):
        """Method to stop the monitoring."""
        self.stop_event.set()

    def cleanup(self):
        """Cleanup resources and close database connections."""
        with self.db_lock:  # Ensure thread-safe cleanup
            if self.conn:
                self.conn.commit()
                self.conn.close()

    def create_table(self, create_sql):
        """Create the necessary database table if it doesn't exist."""
        with self.db_lock:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            with self.conn:
                self.conn.execute(create_sql)
    
    def is_known(self, query_sql, value):
        """Check if an entry is already known in the database."""
        threshold_date = (datetime.now() - timedelta(days=self.expiration)).strftime('%Y-%m-%d %H:%M:%S')
        with self.db_lock:
            if self.conn is None:
                return False
            cursor = self.conn.cursor()
            cursor.execute(query_sql, (value, threshold_date))
            return cursor.fetchone() is not None