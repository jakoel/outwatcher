import requests
import sqlite3
from datetime import datetime
import ipaddress
from collections import deque

class OSINT:
    def __init__(self, print_lock ,vt_api_key, otx_api_key, domain_db_path, ip_db_path, dns_db_lock, ip_db_lock):
        self.vt_api_key = vt_api_key
        self.otx_api_key = otx_api_key
        self.domain_db_path = domain_db_path
        self.ip_db_path = ip_db_path
        self.dns_db_lock = dns_db_lock
        self.ip_db_lock = ip_db_lock
        
    def is_valid_public_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Return True only if the IP is not private, loopback, reserved, or multicast
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast)
        except ValueError:
            # If ipaddress throws an error, it means the IP is invalid
            return False
        
    def check_virus_total(self, data):       
        try:
            # Determine if 'data' is a valid IP address
            ip_obj = ipaddress.ip_address(data[0])
            is_ip = True
        except ValueError:
            is_ip = False
        
        # If it's an IP address, check if it's public
        if is_ip:
            if not self.is_valid_public_ip(data[0]):
                print(f"Skipping non-public or invalid IP: {data[0]}")
                return

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{data[0]}" if is_ip else f"https://www.virustotal.com/api/v3/domains/{data[0]}"
        headers = {"x-apikey": self.vt_api_key}

        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                json_response = response.json()
                positives = json_response['data']['attributes']['last_analysis_stats']['malicious']
                tags = json_response['data']['attributes']['tags']
                print(f"[{data[0]}] - VT Detections: {positives} tags: {tags}")

                # Update the appropriate database
                if is_ip:
                    with self.ip_db_lock:
                        conn = sqlite3.connect(self.ip_db_path)
                        self.update_info(conn, data, positives, tags ,self.ip_db_path)
                        conn.close()
                else:
                    with self.dns_db_lock:
                        conn = sqlite3.connect(self.domain_db_path)
                        self.update_info(conn, data, positives, tags, self.domain_db_path)
                        conn.close()
            else:
                print(f"Failed to retrieve data for {data[0]}: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"An error occurred while checking {data[0]}: {e}", exc_info=True)

    def check_otx(self, indicator):
        try:
            ipaddress.ip_address(indicator)
            is_ip = True
        except ValueError:
            is_ip = False

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general" if is_ip else f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
        headers = {"X-OTX-API-KEY": self.otx_api_key}

        indicator_facts = set()  # Using a set to automatically handle duplicate tags
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_response = response.json()
                
                # Check for pulse_info and extract tags
                if 'pulse_info' in json_response and 'pulses' in json_response['pulse_info']:
                    for pulse in json_response['pulse_info']['pulses']:
                        if 'tags' in pulse and pulse['tags']:  # Check if 'tags' exists and is not empty
                            indicator_facts.update(pulse["tags"])  # Add tags to set (no duplicates)
                
                # Only print if indicator_facts has tags
                if indicator_facts:
                    # Convert set to list, and limit to 5 tags
                    limited_tags = list(indicator_facts)[:5]
                    print(f"[{indicator}] OTX Tags: {', '.join(limited_tags)}")
            else:
                print(f"Failed to retrieve indicator facts for {indicator}: {response.status_code} - {response.text}")
                        
        except Exception as e:
            print(f"An error occurred while retrieving facts for {indicator}: {e}")


                 
    def update_info(self, conn, value, positives, tags, db_path):
        now = datetime.now()
        cursor = conn.cursor()
        
        try:
            if db_path.endswith('domains.db'):
                cursor.execute('''
                    INSERT INTO known_domains (domain, last_check, positives, tags)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        last_check = excluded.last_check,
                        positives = excluded.positives,
                        tags = excluded.tags
                ''', (value[0], now, positives, ', '.join(tags)))
                
            else:
                cursor.execute('''
                    INSERT INTO known_ips (ip, last_check, positives, tags, process_name)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        last_check = excluded.last_check,
                        positives = excluded.positives,
                        tags = excluded.tags,
                        process_name = excluded.process_name
                ''', (value[0], now, positives, ', '.join(tags), value[1]))
            
            conn.commit()
        except sqlite3.Error as e:
            print(f"An error occurred while updating the database: {e}")
            conn.rollback()
        finally:
            cursor.close()

def get_api_key(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readline().strip()
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
    except Exception as e:
        print(f"An error occurred while reading the API key: {e}")
    return None