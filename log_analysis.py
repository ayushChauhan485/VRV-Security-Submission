import re
import csv
from collections import Counter
from tabulate import tabulate

# Function to parse the log file
def parse_log(file_path):
    with open(file_path, 'r') as log_file:
        lines = log_file.readlines()
    return lines

# Function to count requests per IP address
def count_requests(log_lines):
    ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ip_counter = Counter(re.match(ip_pattern, line).group(1) for line in log_lines if re.match(ip_pattern, line))
    return ip_counter

# Function to identify the most accessed endpoint
def most_accessed_endpoint(log_lines):
    endpoint_pattern = r'"[A-Z]+\s([^\s]+)\sHTTP'
    endpoint_counter = Counter(re.search(endpoint_pattern, line).group(1) for line in log_lines if re.search(endpoint_pattern, line))
    most_common_endpoint = endpoint_counter.most_common(1)[0]
    return most_common_endpoint

# Function to detect suspicious activity
def detect_suspicious_activity(log_lines, threshold=10):
    suspicious_ips = Counter()
    for line in log_lines:
        if ' 401 ' in line or "Invalid credentials" in line:
            ip = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line).group(1)
            suspicious_ips[ip] += 1
    flagged_ips = {ip: count for ip, count in suspicious_ips.items() if count > threshold}
    return flagged_ips

# Function to save results to a CSV file
def save_to_csv(ip_counts, most_accessed, suspicious_ips, output_file='log_analysis_results.csv'):
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_counts.items())

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed)

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        writer.writerows(suspicious_ips.items())

# Main function to run the analysis
def main():
    log_file_path = 'sample.log'  # Change this to the actual log file path
    log_lines = parse_log(log_file_path)

    # Analyze log
    ip_counts = count_requests(log_lines)
    most_accessed = most_accessed_endpoint(log_lines)
    suspicious_ips = detect_suspicious_activity(log_lines)

    # Display results in terminal
    print("Requests per IP Address:")
    print(tabulate(ip_counts.items(), headers=['IP Address', 'Request Count'], tablefmt='grid'))

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(tabulate(suspicious_ips.items(), headers=['IP Address', 'Failed Login Attempts'], tablefmt='grid'))

    # Save results to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'")

if __name__ == "__main__":
    main()
