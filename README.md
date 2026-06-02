> 🚧 Under active rebuild: migrating from v0.1 (Flask) to v2.0 (FastAPI). README being updated.

# # ThreatCheck V0.1 (OSNIT)

## Overview
This tool is a Python-based web application that:
- Monitors active network connections.
- Checks remote IP reputation using **AbuseIPDB**.
- Provides a **web interface** for visualization.
- Supports **Docker deployment** for easy usage.

## Features
✅ Retrieves active network connections (IP addresses, statuses).  
✅ Queries **AbuseIPDB** to check if an IP has been reported as malicious.  
✅ Simple **Flask-based web UI** for scanning results.  
✅ **Dockerized** for easy deployment and execution.  

## Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/amessedad/threatcheck.git
cd threatcheck
```

### 2️⃣ Install Dependencies
Ensure Python 3.9+ is installed.
```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Application
```bash
python threatcheck.py
```
Access the web UI at:  
👉 `http://localhost:9090`

---

---

## API Endpoints
- **GET /** → Home Page (Web UI)  
- **GET /scan** → Retrieves network connections & checks reputation  

---

## Example Output
```json
[
  {
    "connection": {"local_ip": "192.168.1.10", "remote_ip": "8.8.8.8", "status": "ESTABLISHED"},
    "reputation": {"abuseConfidenceScore": 0}
  }
]
```

---

## Configuration
To use AbuseIPDB API, replace `YOUR_ABUSEIPDB_API_KEY` in `threatcheck.py` with your own API key.

---

---
## Future Features 
Enhance the solution by integrating AI capabilities, enabling the application to leverage a Generative AI model for analyzing responses from OSINT tools.
---

## Contributors
👤 **Abderrezzaq Messedad**  
📧 Contact: a.messedad@gmail.com

---

## License
📝 No License 

