import subprocess
from scapy.all import rdpcap, IP
import pandas as pd
from collections import defaultdict
import joblib
import requests
import time
import os

# ==== CONFIG ====
# Interface to capture on:
INTERFACE = "wlan0"        # your Pi uses Wi-Fi
CAP_FILE = "live_capture.pcap"

# Replace this with your laptop's IP (from ipconfig)
LAPTOP_IP = "192.168.98.252"   # <-- CHANGE THIS if network changes
SERVER_URL = f"http://{LAPTOP_IP}:5000/alert"

MODEL_FILE = "ids_rf.joblib"
PACKET_LIMIT = 100  # capture 100 packets each run (tune as needed)
# =================


def capture_pcap():
    print(f"[+] Capturing {PACKET_LIMIT} packets on {INTERFACE} ...")
    cmd = [
        "tcpdump",
        "-i", INTERFACE,
        "-s", "0",
        "-c", str(PACKET_LIMIT),
        "-w", CAP_FILE
    ]
    subprocess.run(cmd, check=True)
    print(f"[+] Capture complete -> {CAP_FILE}")


def extract_flows(pcap_file):
    print(f"[+] Reading packets from {pcap_file} ...")
    pkts = rdpcap(pcap_file)

    # For each flow (src, dst, sport, dport, proto)
    # we store packet sizes and timestamps
    flows = defaultdict(lambda: {"sizes": [], "times": []})

    for pkt in pkts:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            sport = getattr(pkt, "sport", 0)
            dport = getattr(pkt, "dport", 0)
            key = (src, dst, sport, dport, proto)

            flows[key]["sizes"].append(len(pkt))
            # pkt.time is a float timestamp (seconds)
            flows[key]["times"].append(float(pkt.time))

    print(f"[+] Total flows extracted: {len(flows)}")

    rows = []
    for key, data in flows.items():
        src, dst, sport, dport, proto = key
        sizes = data["sizes"]
        times = data["times"]

        if not sizes or not times:
            continue

        packet_count = len(sizes)
        total_bytes = sum(sizes)
        avg_len = total_bytes / packet_count

        start_ts = min(times)
        end_ts = max(times)
        duration = max(end_ts - start_ts, 1e-6)  # avoid divide by zero

        flow_bytes_per_s = total_bytes / duration
        flow_pkts_per_s = packet_count / duration

        rows.append({
            # Features matching CICIDS2017 training:
            "Flow Duration": duration,
            "Total Fwd Packets": packet_count,             # approximate
            "Total Length of Fwd Packets": total_bytes,    # approximate
            "Packet Length Mean": avg_len,
            "Flow Bytes/s": flow_bytes_per_s,
            "Flow Packets/s": flow_pkts_per_s,

            # Extra fields for alerts:
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "packet_count": packet_count,
            "total_bytes": total_bytes,
        })

    df = pd.DataFrame(rows)
    print(f"[+] Created DataFrame with {len(df)} rows")
    return df


def load_model():
    print(f"[+] Loading model from {MODEL_FILE} ...")
    clf = joblib.load(MODEL_FILE)
    print("[+] Model loaded.")
    return clf


def detect_suspicious(df, clf):
    if df.empty:
        print("[!] No flows to analyze.")
        return df  # empty

    feature_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Length of Fwd Packets",
        "Packet Length Mean",
        "Flow Bytes/s",
        "Flow Packets/s",
    ]

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in flow data: {missing}")

    X = df[feature_cols]

    if hasattr(clf, "predict_proba"):
        probs = clf.predict_proba(X)[:, 1]  # probability of attack
        df["attack_score"] = probs

        # 👉 NEW: print basic stats so we see how "suspicious" flows are
        print(
            f"[+] attack_score stats: "
            f"min={probs.min():.3f}, max={probs.max():.3f}, mean={probs.mean():.3f}"
        )

        # Threshold can be tuned; start with 0.5 for now (more aggressive)
        THRESHOLD = 0.5
        df["predicted_label"] = (df["attack_score"] > THRESHOLD).astype(int)
    else:
        preds = clf.predict(X)
        df["predicted_label"] = preds
        df["attack_score"] = df["predicted_label"]

    df["predicted_class"] = df["predicted_label"].map({0: "normal", 1: "suspicious"})

    suspicious = df[df["predicted_label"] == 1]
    print(f"[+] Suspicious flows: {len(suspicious)} (threshold-based)")
    return suspicious


def send_alerts(suspicious_df):
    if suspicious_df.empty:
        print("[+] No suspicious flows to send.")
        return

    print(f"[+] Sending alerts to {SERVER_URL} ...")
    for idx, row in suspicious_df.iterrows():
        attack_score = float(row.get("attack_score", -1.0))
        payload = {
            "ts": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src": row.get("src", "unknown"),
            "dst": row.get("dst", "unknown"),
            "sport": int(row.get("sport", 0)),
            "dport": int(row.get("dport", 0)),
            "proto": int(row.get("proto", 0)),
            "predicted_class": row.get("predicted_class", "suspicious"),
            "packet_count": int(row.get("packet_count", 0)),
            "total_bytes": int(row.get("total_bytes", 0)),
            "attack_score": attack_score,
        }
        try:
            r = requests.post(SERVER_URL, json=payload, timeout=5)
            print(f"    Sent alert for flow {idx}, status: {r.status_code}")

            # OPTIONAL: Demo auto-block for suspicious flows
            # Be careful: this will block the SOURCE IP at firewall level.
            src_ip = row.get("src", None)

            # Only block if:
            # - src_ip is local
            # - score is high enough
            # - packet_count is large
            if src_ip and src_ip.startswith("192.168.") \
               and attack_score > 0.8 \
               and int(row.get("packet_count", 0)) > 50:
                print(f"    [BLOCK] Calling block_ip.sh for {src_ip}")
                os.system(f"sudo /home/pi/block_ip.sh {src_ip}")

        except Exception as e:
            print(f"    Error sending alert for flow {idx}: {e}")
        time.sleep(0.2)


def main():
    clf = load_model()

    while True:
        print("\n========== New Capture Round ==========")
        capture_pcap()
        df = extract_flows(CAP_FILE)
        if df.empty:
            print("[!] No flows extracted; sleeping 5 seconds...")
            time.sleep(5)
            continue

        suspicious = detect_suspicious(df, clf)
        send_alerts(suspicious)
        print("[+] Sleeping 10 seconds before next round...")
        time.sleep(10)


if __name__ == "__main__":
    main()
