import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

df = pd.read_csv("speedtest_payload_log.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

plt.figure(figsize=(12, 6))

for op, label in [("did_time", "DID Registration"), ("vc_time", "VC Creation"), ("revoke_time", "VC Revocation")]:
    plt.plot(df["timestamp"], df[op], label=label)

plt.xlabel("Timestamp")
plt.ylabel("Latency (seconds)")
plt.title("Latency Over Time Across Payload Sizes")
plt.xticks(rotation=45)
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("latency_over_time_payload.png")
print("✅ Saved: latency_over_time_payload.png")
