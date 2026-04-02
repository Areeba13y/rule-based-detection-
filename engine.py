import json
from datetime import datetime, timedelta
from collections import defaultdict
import psutil

# -------------------------
# Load & Parse Logs
# -------------------------
def load_logs(file_path="logs.json"):
    try:
        with open(file_path, "r") as f:
            raw_logs = json.load(f)
    except:
        print("[ERROR] logs.json not found or invalid.")
        return []

    parsed_logs = []

    for log in raw_logs:
        try:
            parsed_logs.append({
                "timestamp": datetime.fromisoformat(log["timestamp"]),
                "source_ip": log["source_ip"],
                "destination_ip": log["destination_ip"],
                "protocol": log["protocol"],
                "port": log["port"],
                "event": log["event"]
            })
        except:
            continue

    return parsed_logs


# -------------------------
# Alert System
# -------------------------
def save_alert(message):
    with open("alerts.txt", "a") as f:
        f.write(message + "\n")


def alert(level, message):
    formatted = f"[{level}] {message}"
    print(formatted)
    save_alert(formatted)


# -------------------------
# Detection Rules
# -------------------------

# 🔴 Brute Force Detection
def detect_bruteforce(logs):
    attempts = defaultdict(list)

    for log in logs:
        if log["event"] == "ssh_attempt":
            attempts[log["source_ip"]].append(log["timestamp"])

    for ip, times in attempts.items():
        times.sort()

        for i in range(len(times)):
            window = [
                t for t in times
                if times[i] <= t <= times[i] + timedelta(seconds=60)
            ]

            if len(window) > 5:
                alert("HIGH", f"Brute force detected from {ip}")
                break


# 🟠 Port Scan Detection
def detect_port_scan(logs):
    ports_by_ip = defaultdict(set)

    for log in logs:
        if log["port"]:
            ports_by_ip[log["source_ip"]].add(log["port"])

    for ip, ports in ports_by_ip.items():
        if len(ports) > 10:
            alert("MEDIUM", f"Port scan detected from {ip}")


# 🟡 Traffic Spike Detection
def detect_traffic_spike(logs):
    count_by_ip = defaultdict(int)

    for log in logs:
        count_by_ip[log["source_ip"]] += 1

    for ip, count in count_by_ip.items():
        if count > 100:
            alert("LOW", f"Unusual traffic spike from {ip}")


# -------------------------
# 🆕 Investigation Feature
# -------------------------
def investigate_ip(target_ip):
    results = []

    for conn in psutil.net_connections(kind='inet'):
        try:
            local_ip = conn.laddr.ip if conn.laddr else None
            remote_ip = conn.raddr.ip if conn.raddr else None

            if target_ip == local_ip or target_ip == remote_ip:
                proc_name = "Unknown"
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except:
                        pass

                results.append({
                    "local_ip": local_ip,
                    "remote_ip": remote_ip,
                    "port": conn.laddr.port if conn.laddr else None,
                    "pid": conn.pid,
                    "process": proc_name,
                    "status": conn.status
                })
        except:
            continue

    return results

# -------------------------
# Main Detection Engine
# -------------------------
def run_detection():
    print("[*] Loading logs...")
    logs = load_logs()

    if not logs:
        print("[!] No logs to analyze.")
        return

    print(f"[*] Analyzing {len(logs)} logs...\n")

    # Clear previous alerts (important)
    open("alerts.txt", "w").close()

    detect_bruteforce(logs)
    detect_port_scan(logs)
    detect_traffic_spike(logs)

    print("\n[*] Detection complete.")


# -------------------------
# Entry Point
# -------------------------
if __name__ == "__main__":
    run_detection()