from flask import Flask, request, jsonify
from datetime import datetime
import sqlite3
import time
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "alerts.db")

app = Flask(__name__)

# 1) Create DB if not exists
def init_db():
    print("Using DB file:", DB_NAME)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            src TEXT,
            dst TEXT,
            sport INTEGER,
            dport INTEGER,
            proto INTEGER,
            predicted_class TEXT,
            packet_count INTEGER,
            total_bytes INTEGER,
            attack_score REAL
        )
    """)
    conn.commit()
    conn.close()

# 2) Route to receive alert (Pi or local script will call this)
@app.route("/alert", methods=["POST"])
def receive_alert():
    data = request.json or {}

    # Read fields from JSON (with defaults)
    ts = data.get("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
    src = data.get("src", "unknown")
    dst = data.get("dst", "unknown")
    sport = int(data.get("sport", 0) or 0)
    dport = int(data.get("dport", 0) or 0)
    proto = int(data.get("proto", 0) or 0)
    predicted_class = data.get("predicted_class", "unknown")
    packet_count = int(data.get("packet_count", 0) or 0)
    total_bytes = int(data.get("total_bytes", 0) or 0)
    attack_score = data.get("attack_score", None)
    try:
        attack_score = float(attack_score) if attack_score is not None else None
    except (TypeError, ValueError):
        attack_score = None

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (ts, src, dst, sport, dport, proto,
                            predicted_class, packet_count, total_bytes, attack_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, src, dst, sport, dport, proto,
          predicted_class, packet_count, total_bytes, attack_score))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"}), 200

# 3) Route to view alerts (JSON)
@app.route("/alerts", methods=["GET"])
def list_alerts():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        SELECT ts, src, dst, sport, dport, proto,
               predicted_class, packet_count, total_bytes, attack_score
        FROM alerts
        ORDER BY id DESC
        LIMIT 50
    """)
    rows = cur.fetchall()
    conn.close()

    alerts = []
    for r in rows:
        alerts.append({
            "ts": r[0],
            "src": r[1],
            "dst": r[2],
            "sport": r[3],
            "dport": r[4],
            "proto": r[5],
            "predicted_class": r[6],
            "packet_count": r[7],
            "total_bytes": r[8],
            "attack_score": r[9],
        })

    return jsonify({"alerts": alerts})

# 4) Simple HTML page (landing)
@app.route("/")
def index():
    return """
    <html>
    <head><title>IDS Alerts</title></head>
    <body>
    <h1>Intrusion Detection Alerts</h1>
    <p>Go to <a href="/dashboard">/dashboard</a> for the live dashboard, or <a href="/alerts">/alerts</a> for raw JSON.</p>
    </body>
    </html>
    """

@app.route("/dashboard")
def dashboard():
    return """
    <html>
    <meta http-equiv="refresh" content="5">
    <head>
        <title>IDS Dashboard</title>
        <style>
            body { font-family: Arial; margin: 30px; background: #111; color: #eee; }
            h1 { color: #0f0; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #555; padding: 8px; text-align: left; }
            th { background: #222; color: #0f0; }
            tr:nth-child(even) { background: #1a1a1a; }
            .bad { color: #f33; font-weight: bold; }
            .good { color: #3f3; font-weight: bold; }
        </style>
    </head>
    <body>
    <h1>🔐 Intrusion Detection Dashboard</h1>
    <p>This page refreshes every 5 seconds.</p>

    <div id="summary"></div>
    <br/>
    <div id="data"></div>

    <script>
    async function loadAlerts() {
        let res = await fetch("/alerts");
        let data = await res.json();
        let alerts = data.alerts || [];

        let total = alerts.length;
        let suspicious = alerts.filter(a => a.predicted_class === "suspicious").length;
        let lastTs = total > 0 ? alerts[0].ts : "N/A";

        document.getElementById("summary").innerHTML =
            `<b>Total alerts loaded:</b> ${total} | ` +
            `<b>Suspicious:</b> ${suspicious} | ` +
            `<b>Last alert time:</b> ${lastTs}`;

        let tableHTML = "<table>";
        tableHTML += "<tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Packets</th><th>Bytes</th><th>Score</th><th>Status</th></tr>";

        for (let a of alerts) {
            let cls = a.predicted_class === "suspicious" ? "bad" : "good";
            let score = (a.attack_score === null || a.attack_score === undefined) ? "N/A" : a.attack_score.toFixed(3);
            tableHTML += `
                <tr>
                    <td>${a.ts}</td>
                    <td>${a.src}</td>
                    <td>${a.dst}</td>
                    <td>${a.proto}</td>
                    <td>${a.packet_count}</td>
                    <td>${a.total_bytes}</td>
                    <td>${score}</td>
                    <td class="${cls}">${a.predicted_class}</td>
                </tr>`;
        }

        tableHTML += "</table>";
        document.getElementById("data").innerHTML = tableHTML;
    }

    loadAlerts();
    setInterval(loadAlerts, 5000);
    </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    init_db()
    print("Starting Flask server on http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
