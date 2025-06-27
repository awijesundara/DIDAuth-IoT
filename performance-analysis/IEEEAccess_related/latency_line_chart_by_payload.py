import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

           
df = pd.read_csv("speedtest_payload_log.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

                       
operations = {
    "did_time": "DID Registration Latency",
    "vc_time": "VC Creation Latency",
    "revoke_time": "VC Revocation Latency"
}

for column, title in operations.items():
    plt.figure(figsize=(10, 6))

    for payload_size in sorted(df["payload_size"].unique()):
        subset = df[df["payload_size"] == payload_size]
        plt.plot(subset["timestamp"], subset[column], label=f"{payload_size}B")

    plt.title(title)
    plt.xlabel("Timestamp")
    plt.ylabel("Latency (seconds)")
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.legend(title="Payload Size")
    plt.tight_layout()

                                                
    filename = f"{column}_line_chart_by_payload.png"
    plt.savefig(filename)
    print(f"✅ Saved: {filename}")
