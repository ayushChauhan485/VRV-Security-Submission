# VRV-Security-Submission
# Log Analysis Script

This repository contains a Python script to analyze web server log files, fulfilling the requirements of VRV Security's Python Intern assignment.

## **Features**
1. **Count Requests per IP Address**:
   - Displays the number of requests made by each IP address.
   - Results are sorted in descending order.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts and identifies the most frequently accessed endpoint (e.g., `/home`).

3. **Detect Suspicious Activity**:
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).

4. **Output Results**:
   - Displays results in the terminal and saves them to a structured CSV file.

## **Usage**

### **Requirements**
- Python 3.x
- No additional libraries required.

### **Steps to Run**
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/log-analysis-assignment.git
   cd log-analysis-assignment
