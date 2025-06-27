import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

df = pd.read_csv("speedtest_payload_log.csv")

def plot_percentile(data, label):
    sorted_data = data.sort_values().reset_index(drop=True)
    percentiles = sorted_data.index / (len(sorted_data) - 1) * 100
    plt.plot(percentiles, sorted_data, label=label)

plt.figure(figsize=(10, 6))

for payload in sorted(df["payload_size"].unique()):
    subset = df[df["payload_size"] == payload]
    plot_percentile(subset["vc_time"], f"{payload}B")

plt.xlabel("Percentile")
plt.ylabel("VC Creation Latency (seconds)")
plt.title("VC Creation Latency by Percentile (Grouped by Payload Size)")
plt.legend(title="Payload Size")
plt.grid(True)
plt.tight_layout()
plt.savefig("vc_percentile_by_payload.png")
print("✅ Saved: vc_percentile_by_payload.png")
