import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

               
df = pd.read_csv("speedtest_payload_log.csv")

                               
fig, axs = plt.subplots(3, 1, figsize=(10, 15))
fig.suptitle("Latency Percentile Distribution by Payload Size", fontsize=16)

                                    
def plot_percentile(ax, data_series, label):
    sorted_data = data_series.sort_values().reset_index(drop=True)
    percentiles = sorted_data.index / (len(sorted_data) - 1) * 100
    ax.plot(percentiles, sorted_data, label=label)

                                  
for size in sorted(df["payload_size"].unique()):
    subset = df[df["payload_size"] == size]
    plot_percentile(axs[0], subset["did_time"], f"{size}B")

axs[0].set_title("DID Registration Latency")
axs[0].set_ylabel("Latency (seconds)")
axs[0].grid(True)
axs[0].legend(title="Payload Size")

                             
for size in sorted(df["payload_size"].unique()):
    subset = df[df["payload_size"] == size]
    plot_percentile(axs[1], subset["vc_time"], f"{size}B")

axs[1].set_title("VC Creation Latency")
axs[1].set_ylabel("Latency (seconds)")
axs[1].grid(True)
axs[1].legend(title="Payload Size")

                               
for size in sorted(df["payload_size"].unique()):
    subset = df[df["payload_size"] == size]
    plot_percentile(axs[2], subset["revoke_time"], f"{size}B")

axs[2].set_title("VC Revocation Latency")
axs[2].set_xlabel("Percentile")
axs[2].set_ylabel("Latency (seconds)")
axs[2].grid(True)
axs[2].legend(title="Payload Size")

                 
plt.tight_layout(rect=[0, 0, 1, 0.97])
plt.savefig("latency_percentile_all_ops_by_payload.png")
print("✅ Saved: latency_percentile_all_ops_by_payload.png")
