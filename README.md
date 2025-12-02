🛡️ Raspberry Pi Real-Time Machine Learning Intrusion Detection System (IDS)

A full end-to-end IDS project that runs on a Raspberry Pi using live packet capture, flow-based feature extraction, a trained machine-learning model, and a Flask web dashboard for real-time alert visualization.

This project is designed for:

✔️ Cybersecurity research
✔️ College assignments
✔️ Placement portfolios
✔️ Real-world networking demos

🌟 Key Features

🔹 Real-time packet capture using tcpdump
🔹 Flow extraction using Scapy
🔹 Machine Learning trained on CICIDS2017 dataset
🔹 One-click Flask web dashboard
🔹 Alerts stored in SQLite
🔹 Optional auto-blocking IPs via iptables
🔹 Lightweight, edge-friendly design

🏛️ System Architecture

Raspberry Pi (Edge Device → AI IDS)

Raw Packets → Flow Features → ML Model → Suspicious? → Send JSON Alert


Laptop / Server

Receive Alerts → SQLite Database → Live Dashboard UI

┌─────────────────────────┐                 ┌─────────────────────────┐
│  Raspberry Pi IDS       │  HTTP POST JSON │       Flask Server      │
│  ─ tcpdump              ├────────────────►│  /alert API endpoint    │
│  ─ scapy flow features  │                 │  SQLite storage         │
│  ─ ML inference         │                 │  /dashboard live UI     │
└─────────────────────────┘                 └─────────────────────────┘

📂 Project Structure
RaspberryPi-IDS/
│
├─ src/
│   ├─ app.py               # Flask backend + REST
│   ├─ pi_ids_agent.py      # Raspberry Pi IDS agent
│   └─ train_model_cicids.py# Model training script
│
├─ models/
│   └─ ids_rf.joblib        # Trained ML model
│
├─ dataset/
│   └─ sample_flows.csv  (Large dataset not included)
│
├─ scripts/
│   └─ block_ip.sh          # Optional firewall blocking
│
├─ docs/                    # Screenshots + diagrams
│   ├─ dashboard.png
│   ├─ architecture.png
│   └─ pi_terminal.png
│
├─ requirements.txt
└─ README.md

🚀 Installation & Setup
1️⃣ Clone the repository
git clone https://github.com/Aash55/RaspberryPi-IDS.git
cd RaspberryPi-IDS

2️⃣ Create virtual environment (Laptop / Server)
Windows
python -m venv venv
venv\Scripts\activate

Linux/Mac
python3 -m venv venv
source venv/bin/activate

3️⃣ Install dependencies
pip install -r requirements.txt

🌐 Run the Flask Alert Server (Laptop)
python src/app.py


You should see:

Running on http://127.0.0.1:5000


Now open:

🔗 Dashboard → http://127.0.0.1:5000/dashboard

🔗 Alerts JSON → http://127.0.0.1:5000/alerts

🐍 Run IDS Agent on Raspberry Pi
1️⃣ Copy ML model
scp models/ids_rf.joblib pi@<pi-ip>:/home/pi/

2️⃣ Copy IDS agent
scp src/pi_ids_agent.py pi@<pi-ip>:/home/pi/

3️⃣ Run IDS
sudo python3 pi_ids_agent.py


It will:

✔️ Capture packets
✔️ Extract flows
✔️ Run ML inference
✔️ POST alerts

📦 Alert JSON Format

Example alert sent from Raspberry Pi:

{
  "ts": "2025-12-02 15:03:21",
  "src": "192.168.46.12",
  "dst": "8.8.8.8",
  "sport": 52311,
  "dport": 443,
  "proto": 6,
  "predicted_class": "suspicious",
  "packet_count": 99,
  "total_bytes": 12345
}

🧠 Machine Learning Model
Dataset

📡 CICIDS2017 — Cleaned & Preprocessed Version

Contains:

Normal traffic

DoS / DDoS

Port scan

Botnet traffic

Brute force

Web attacks

Selected Features

Light, edge-friendly features used both in training + runtime:

Flow Duration
Total Fwd Packets
Total Length of Fwd Packets
Packet Length Mean
Flow Bytes/s
Flow Packets/s


These work well for anomaly detection on small hardware.

Algorithm

✔️ RandomForestClassifier

200 trees

max depth 15

class_weight="balanced"

low inference cost

robust to noise

Training Script

Located at:

src/train_model_cicids.py


Outputs:

models/ids_rf.joblib

🔥 Optional: Auto IP Blocking

Only in controlled networks ⚠️

sudo iptables -I INPUT -s <ip> -j DROP


Script:

scripts/block_ip.sh


It protects from:

✔️ Port Scans
✔️ DoS / Flooding
✔️ Suspicious high-volume flows

🔒 Cybersecurity Ethics

🚨 Do not use on networks you do not own
🚨 Do not inspect personal user traffic
🚨 Never deploy auto-block on public networks
🚨 Use only for research, education, demo

This project is educational, not a commercial IPS/IDS.

🧭 Why This Is Placement-Ready

✔ IoT Edge 🛰️
✔ Cybersecurity 🔐
✔ Machine Learning 🤖
✔ Networking (TCP/IP) 🌐
✔ Web development (Flask + JS UI) 🖥️
✔ Real-time data pipeline ⚡
✔ SQLite data persistence 🗂️

This shows you can build complete systems, not just simple scripts.

🚀 Future Enhancements

🔹 Train with more classes → multi-class IDS
🔹 Add Suricata/Snort rule engine
🔹 Grafana / Kibana dashboards
🔹 TensorFlow Lite edge inference
🔹 JWT authentication for dashboard
🔹 TimescaleDB for time-series alerts

📜 License

MIT License — Free for research and education.

⭐ Support & Contributions

Enjoy this project?
🔹 Star ⭐ the repository
🔹 Open issues
🔹 Suggest improvements
🔹 Fork and submit PRs

🙏 Credits

Developed by ASH55(M.Tech Student)
with learning support from Angela Yu, CIC Lab, and helpful tools like Scapy, Flask & RandomForest ML.

💬 Contact

If you need help:

Open an issue

DM on GitHub

Ask via discussions

Security + AI + IoT = Your Superpower 🚀
Build systems, not just code.

⭐ If this helped, please drop a star 🌟