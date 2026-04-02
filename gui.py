import tkinter as tk
import subprocess
import json
import os
import ctypes
import threading

from engine import investigate_ip

ctypes.windll.user32.SetProcessDPIAware()

BG_COLOR = "#1e1e1e"
FG_COLOR = "#ffffff"
ACCENT = "#1625CA"
BOX_BG = "#121212"

# ------------------------
# Capture (LIVE)
# ------------------------

def run_capture():
    threading.Thread(target=_run_capture).start()

def _run_capture():
    status_label.config(text="Running capture...")

    process = subprocess.Popen(
        ["python", "capture.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    packet_box.config(state="normal")
    packet_box.delete(1.0, tk.END)

    for line in iter(process.stdout.readline, ''):
        packet_box.insert(tk.END, line)
        packet_box.see(tk.END)
        root.update()

    packet_box.config(state="disabled")
    status_label.config(text="Capture complete.")

# ------------------------
# Detection
# ------------------------

def run_detection():
    threading.Thread(target=_run_detection).start()

def _run_detection():
    status_label.config(text="Running detection...")
    subprocess.run(["python", "engine.py"])
    status_label.config(text="Detection complete.")
    load_alerts()
    update_stats()

# ------------------------
# Alerts
# ------------------------

def load_alerts():
    alerts_box.config(state="normal")
    alerts_box.delete(1.0, tk.END)

    if os.path.exists("alerts.txt"):
        with open("alerts.txt", "r") as f:
            for line in f:
                if "[HIGH]" in line:
                    alerts_box.insert(tk.END, line, "high")
                elif "[MEDIUM]" in line:
                    alerts_box.insert(tk.END, line, "medium")
                else:
                    alerts_box.insert(tk.END, line, "low")
    else:
        alerts_box.insert(tk.END, "No alerts found.\n")

    alerts_box.tag_config("high", foreground="red")
    alerts_box.tag_config("medium", foreground="orange")
    alerts_box.tag_config("low", foreground="yellow")

    alerts_box.config(state="disabled")

# ------------------------
# Stats
# ------------------------

def update_stats():
    try:
        with open("logs.json", "r") as f:
            logs = json.load(f)
            log_count.set(f"Logs: {len(logs)}")
    except:
        log_count.set("Logs: 0")

    try:
        with open("alerts.txt", "r") as f:
            alerts = f.readlines()
            alert_count.set(f"Alerts: {len(alerts)}")
    except:
        alert_count.set("Alerts: 0")

def refresh():
    load_alerts()
    update_stats()

# ------------------------
# Clear Logs
# ------------------------

def clear_logs():
    with open("logs.json", "w") as f:
        json.dump([], f)

    open("alerts.txt", "w").close()

    refresh()
    status_label.config(text="Logs cleared.")

# ------------------------
# Investigation Feature (FIXED + ENHANCED)
# ------------------------

def investigate():
    ip = ip_entry.get().strip()

    result_box.config(state="normal")
    result_box.delete(1.0, tk.END)

    if not ip:
        result_box.insert(tk.END, "Enter an IP address.\n")
        result_box.config(state="disabled")
        return

    results = investigate_ip(ip)

    if not results:
        result_box.insert(
            tk.END,
            "⚠ No active local process found for this IP.\n"
            "This may be a remote host or inactive connection.\n"
        )
    else:
        for r in results:
            result_box.insert(
                tk.END,
                f"[FOUND]\n"
                f"Local IP : {r['local_ip']}\n"
                f"Remote IP: {r['remote_ip']}\n"
                f"Port     : {r['port']}\n"
                f"PID      : {r['pid']}\n"
                f"Process  : {r['process']}\n"
                f"State    : {r['status']}\n"
                f"{'-'*40}\n"
            )

    result_box.config(state="disabled")

# ------------------------
# GUI
# ------------------------

root = tk.Tk()
root.title("Mini IDS Dashboard")
root.geometry("1200x750")
root.configure(bg=BG_COLOR)

# Title
title = tk.Label(
    root,
    text="Intrusion Detection System",
    font=("Algerian", 18),
    bg=BG_COLOR,
    fg=ACCENT
)
title.pack(pady=10)

# Buttons
btn_frame = tk.Frame(root, bg=BG_COLOR)
btn_frame.pack(pady=5)

def btn(text, cmd):
    return tk.Button(
        btn_frame,
        text=text,
        width=15,
        command=cmd,
        bg="#2b2b2b",
        fg=FG_COLOR,
        activebackground=ACCENT,
        relief=tk.FLAT
    )

btn("Start Capture", run_capture).grid(row=0, column=0, padx=10)
btn("Run Detection", run_detection).grid(row=0, column=1, padx=10)
btn("Refresh", refresh).grid(row=0, column=2, padx=10)
btn("Clear Logs", clear_logs).grid(row=0, column=3, padx=10)

# Stats
log_count = tk.StringVar(value="Logs: 0")
alert_count = tk.StringVar(value="Alerts: 0")

stats = tk.Frame(root, bg=BG_COLOR)
stats.pack()

tk.Label(stats, textvariable=log_count, bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=20)
tk.Label(stats, textvariable=alert_count, bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=20)

# Main Panels
main = tk.Frame(root, bg=BG_COLOR)
main.pack()

# Packet Box
packet_box = tk.Text(main, height=18, width=55, bg=BOX_BG, fg="#00bfff")
packet_box.grid(row=0, column=0, padx=10)

# Alerts Box
alerts_box = tk.Text(main, height=18, width=55, bg=BOX_BG)
alerts_box.grid(row=0, column=1, padx=10)

# ------------------------
# Investigation Panel
# ------------------------

invest_frame = tk.Frame(root, bg=BG_COLOR)
invest_frame.pack(pady=10)

tk.Label(invest_frame, text="Investigate IP:", bg=BG_COLOR, fg=FG_COLOR).grid(row=0, column=0, padx=5)

ip_entry = tk.Entry(invest_frame, width=25)
ip_entry.grid(row=0, column=1, padx=5)

tk.Button(
    invest_frame,
    text="Investigate",
    command=investigate,
    bg="#2b2b2b",
    fg=FG_COLOR,
    activebackground=ACCENT
).grid(row=0, column=2, padx=5)

# Result Box
result_box = tk.Text(root, height=8, width=110, bg=BOX_BG, fg="#00ff9c")
result_box.pack(pady=5)

# Status Bar
status_label = tk.Label(root, text="Ready", bg="#2b2b2b", fg=FG_COLOR, anchor=tk.W)
status_label.pack(fill=tk.X)

# Initial Load
refresh()
root.mainloop()