import psutil
import requests
from flask import Flask, render_template, jsonify, request
import docker

# AbuseIPDB API Key (Replace with your own API Key)
API_KEY = "YOUR ABUSEIPDB API KEY"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Flask App
app = Flask(__name__)

def get_network_connections():
    """Retrieve active network connections."""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            connections.append({
                "local_ip": conn.laddr.ip,
                "remote_ip": conn.raddr.ip,
                "status": conn.status
            })
    return connections

def check_ip_reputation(ip):
    """Query AbuseIPDB for IP reputation."""
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
    return response.json() if response.status_code == 200 else {"error": "Failed to fetch"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    """Perform network scan and check reputation."""
    results = []
    connections = get_network_connections()
    for conn in connections:
        reputation = check_ip_reputation(conn["remote_ip"])
        results.append({"connection": conn, "reputation": reputation})
    return jsonify(results)

@app.route('/check_ip', methods=['POST'])
def check_ip():
    """Check a manually entered IP against AbuseIPDB."""
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    reputation = check_ip_reputation(ip)
    return jsonify(reputation)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)

# Dockerfile for containerization
dockerfile = """
FROM python:3.9

# Set working directory inside the container
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Copy all project files
COPY . .

# Ensure the templates folder and index.html exist
RUN mkdir -p templates && chmod -R 777 templates
COPY templates/index.html templates/index.html

# Expose port 9090
EXPOSE 9090

# Run the application
CMD ["python", "threatcheck.py"]
"""

with open("Dockerfile", "w") as f:
    f.write(dockerfile)

# Web UI Template (index.html)
html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Scanner</title>
    <script>
        function scanNetwork() {
            fetch('/scan')
                .then(response => response.json())
                .then(data => {
                    let resultDiv = document.getElementById('results');
                    resultDiv.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                });
        }

        function checkIP() {
            let ip = document.getElementById('ipInput').value.trim();
            let ipResultDiv = document.getElementById('ipResults');
            
            if (!validateIP(ip)) {
                ipResultDiv.innerHTML = '<p style="color: red;">Invalid IP address format.</p>';
                return;
            }

            ipResultDiv.innerHTML = '<p>Checking IP reputation...</p>';

            fetch('/check_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            })
            .then(response => response.json())
            .then(data => {
                ipResultDiv.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(error => {
                ipResultDiv.innerHTML = '<p style="color: red;">Error fetching data.</p>';
            });
        }

        function validateIP(ip) {
            let ipPattern = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
            return ipPattern.test(ip);
        }
    </script>
</head>
<body>
    <h1>Network Security Scanner</h1>
    
    <button onclick="scanNetwork()">Scan Network</button>
    <div id="results"></div>

    <h2>Check IP Reputation</h2>
    <input type="text" id="ipInput" placeholder="Enter IP address">
    <button onclick="checkIP()">Check IP</button>
    <div id="ipResults"></div>
</body>
</html>
"""

with open("templates/index.html", "w") as f:
    f.write(html_template)
