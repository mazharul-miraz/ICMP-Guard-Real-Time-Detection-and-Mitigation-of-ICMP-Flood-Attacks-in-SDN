import pandas as pd
import matplotlib.pyplot as plt
import time

# Correct the file path here
LOG_FILE = 'icmp_rtt_log.csv'  # Ensure this matches the actual file name you have

def update_plot():
    try:
        df = pd.read_csv(LOG_FILE)
    except FileNotFoundError:
        print(f"[!] CSV file {LOG_FILE} not found. Run ICMP Guard first.")
        exit(1)

    # Validate columns
    required_cols = ['timestamp', 'host', 'total', 'rtt']
    for col in required_cols:
        if col not in df.columns:
            print(f"[!] Missing column '{col}' in CSV. Check ICMP Guard logging.")
            exit(1)

    # Convert timestamp to datetime
    df['time'] = pd.to_datetime(df['timestamp'], format="%Y-%m-%dT%H:%M:%SZ")

    # ----------------- Define Attack Detection Time -----------------
    # Example: Find the first occurrence where ICMP count exceeds threshold
    attack_detection_time = df['time'].iloc[50]  # Example: replace with the actual attack detection time
    attack_end_time = df['time'].iloc[60]  # Replace with the mitigation time

    # ----------------- Plotting -----------------
    plt.figure(figsize=(12, 6))

    # Define attack and normal traffic
    attack_hosts = [('10.0.0.1', '10.0.0.3'), ('10.0.0.2', '10.0.0.3')]  # Example IPs for attack (host1 -> host3)

    # Plot traffic for each host
    for host in df['host'].unique():
        host_data = df[df['host'] == host]

        # Separate attack traffic (h1 -> h3) and normal traffic (h2 -> h3)
        if host == '10.0.0.1':  # Attack traffic from h1 to h3
            plt.plot(host_data['time'], host_data['rtt'] * 1000, label=f"{host} -> h3 (Attack)", color='orange', linestyle=':', marker='o', linewidth=2)  # Dotted line style, scaled by 1000
        elif host == '10.0.0.2':  # Normal traffic from h2 to h3
            plt.plot(host_data['time'], host_data['rtt'] * 1000, label=f"{host} -> h3 (Normal)", color='blue', linestyle='-', marker='x', linewidth=2)  # Solid line, scaled by 1000
        else:
            # Other hosts
            plt.plot(host_data['time'], host_data['rtt'] * 1000, label=f"{host} traffic", linestyle='--', color='green', marker='s')  # Dashed line, scaled by 1000

    # Attack detection and mitigation line
    plt.axvline(x=attack_detection_time, color='orange', linestyle='-', linewidth=2, label="Attack Detected & Mitigated")

    # Adjust Y-Axis limits to show spikes clearly
    plt.ylim(0, 1600)  # Setting the y-axis to display a range between 0 and 1600 ms

    # Plotting details
    plt.xlabel("Time")
    plt.ylabel("Latency (RTT) in ms (scaled)")
    plt.title("ICMP Attack Detection and Mitigation")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# Run the plot update
if __name__ == "__main__":
    while True:
        update_plot()
        time.sleep(3)  # Update the plot every 3 seconds (or adjust as needed)

