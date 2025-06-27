import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

df = pd.read_csv("speedtest_payload_log.csv")

                        
payloads = sorted(df["payload_size"].unique())
did = [df[df["payload_size"] == p]["did_time"] for p in payloads]
vc = [df[df["payload_size"] == p]["vc_time"] for p in payloads]
rev = [df[df["payload_size"] == p]["revoke_time"] for p in payloads]

plt.figure(figsize=(10, 6))

positions = range(len(payloads))
width = 0.25

                                                 
plt.boxplot(did, positions=[p - width for p in positions], widths=0.2, patch_artist=True)
plt.boxplot(vc, positions=positions, widths=0.2, patch_artist=True)
plt.boxplot(rev, positions=[p + width for p in positions], widths=0.2, patch_artist=True)

plt.xticks(positions, [str(p) + "B" for p in payloads])
plt.xlabel("Payload Size")
plt.ylabel("Latency (seconds)")
plt.title("Latency Distribution by Payload Size (Boxplot)")
plt.legend(["DID", "VC", "Revoke"])
plt.grid(True)
plt.tight_layout()
plt.savefig("latency_boxplot_by_payload.png")
print("✅ Saved: latency_boxplot_by_payload.png")
