import re
import csv
from collections import Counter, defaultdict

# File paths
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
THRESHOLD = 10  # Configurable threshold for suspicious activity detection

def parse_log_file(log_file):
    ip_counter = Counter()
    endpoint_counter = Counter()
    failed_login_attempts = defaultdict(int)
    
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP Address and Endpoint
            ip_match = re.search(r'^(\S+)', line)
            endpoint_match = re.search(r'"(?:GET|POST) (\S+)', line)
            status_code_match = re.search(r'" (\d{3}) ', line)
            
            if ip_match:
                ip = ip_match.group(1)
                ip_counter[ip] += 1
            
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counter[endpoint] += 1
            
            if status_code_match:
                status_code = status_code_match.group(1)
                if status_code == "401":  # Failed login attempt
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_login_attempts[ip] += 1

    return ip_counter, endpoint_counter, failed_login_attempts

def save_to_csv(ip_data, endpoint_data, suspicious_activity):
    with open(OUTPUT_CSV, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP Requests
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_data:
            writer.writerow([ip, count])
        
        writer.writerow([])  # Empty row for separation
        
        # Write Most Accessed Endpoint
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_data:
            writer.writerow([endpoint, count])
        
        writer.writerow([])  # Empty row for separation
        
        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity:
            writer.writerow([ip, count])

def main():
    ip_counter, endpoint_counter, failed_login_attempts = parse_log_file(LOG_FILE)
    
    # Sort data for display
    sorted_ips = ip_counter.most_common()
    sorted_endpoints = endpoint_counter.most_common()
    suspicious_activity = [(ip, count) for ip, count in failed_login_attempts.items() if count >= THRESHOLD]
    
    # Display results
    print("Requests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    if sorted_endpoints:
        print(f"{sorted_endpoints[0][0]} (Accessed {sorted_endpoints[0][1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in suspicious_activity:
        print(f"{ip:<20} {count:<15}")
    
    # Save to CSV
    save_to_csv(sorted_ips, sorted_endpoints, suspicious_activity)

if __name__ == "__main__":
    main()
