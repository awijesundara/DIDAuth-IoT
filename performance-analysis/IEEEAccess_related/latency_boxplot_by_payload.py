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

                                                  
boxprops = dict(linewidth=1.5)

colors = {
    "DID": "#1f77b4",            
    "VC": "#ff7f0e",               
    "Revoke": "#2ca02c"           
}

          
bp1 = plt.boxplot(did, positions=[p - width for p in positions], widths=0.2,
                  patch_artist=True, boxprops=boxprops)
for patch in bp1['boxes']:
    patch.set_facecolor(colors["DID"])

         
bp2 = plt.boxplot(vc, positions=positions, widths=0.2,
                  patch_artist=True, boxprops=boxprops)
for patch in bp2['boxes']:
    patch.set_facecolor(colors["VC"])

             
bp3 = plt.boxplot(rev, positions=[p + width for p in positions], widths=0.2,
                  patch_artist=True, boxprops=boxprops)
for patch in bp3['boxes']:
    patch.set_facecolor(colors["Revoke"])

               
plt.xticks(positions, [f"{p}B" for p in payloads])
plt.xlabel("Payload Size")
plt.ylabel("Latency (seconds)")
plt.title("Latency Distribution by Payload Size (Boxplot)")
plt.grid(True)
plt.legend([bp1["boxes"][0], bp2["boxes"][0], bp3["boxes"][0]],
           ["DID Create", "VC Create", "Revoke"])
plt.tight_layout()
plt.savefig("latency_boxplot_by_payload.png")
print("✅ Saved: latency_boxplot_by_payload.png")
