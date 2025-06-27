import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

                              
sns.set(style="whitegrid", palette="Set2")

           
valid_df = pd.read_csv("esp32_vc_valid_latency_log.csv")
revoked_df = pd.read_csv("esp32_vc_revoked_latency_log.csv")

              
valid_df["VC_Status"] = "Valid"
revoked_df["VC_Status"] = "Revoked"

                        
df = pd.concat([valid_df, revoked_df], ignore_index=True)

                                       
plt.figure()
sns.lineplot(data=df, x="Attempt", y="TotalTime", hue="VC_Status", marker="o")
plt.title("Total Verification Time vs Attempt")
plt.xlabel("Attempt")
plt.ylabel("Total Time (ms)")
plt.savefig("esp32_total_verification_time_vs_attempt.png")

                                     
plt.figure()
sns.boxplot(data=df, x="VC_Status", y="PostTime")
plt.title("POST Time Distribution")
plt.ylabel("POST Time (ms)")
plt.savefig("esp32_post_time_boxplot.png")

                         
plt.figure()
sns.lineplot(data=df, x="Attempt", y="HeapBefore", label="Heap Before", marker="o")
sns.lineplot(data=df, x="Attempt", y="HeapAfterRead", label="Heap After Read", marker="s")
sns.lineplot(data=df, x="Attempt", y="HeapAfterHTTP", label="Heap After HTTP", marker="^")
plt.title("Heap Usage Over Time")
plt.xlabel("Attempt")
plt.ylabel("Heap (bytes)")
plt.legend()
plt.savefig("esp32_heap_usage_over_time.png")

                          
plt.figure()
sns.scatterplot(data=df, x="VCSize", y="TotalTime", hue="VC_Status", style="VC_Status")
plt.title("VC Size vs Total Time")
plt.xlabel("VC Size (bytes)")
plt.ylabel("Total Time (ms)")
plt.savefig("esp32_vc_size_vs_total_time.png")

                                   
plt.figure()
sns.boxplot(data=df, x="VC_Status", y="WiFiTime")
plt.title("WiFi Connection Time Distribution")
plt.ylabel("WiFi Time (ms)")
plt.savefig("esp32_wifi_time_boxplot.png")

                                    
plt.figure()
sns.countplot(data=df, x="HTTPCode", hue="VC_Status")
plt.title("HTTP Response Code Distribution")
plt.xlabel("HTTP Code")
plt.ylabel("Count")
plt.savefig("esp32_http_code_distribution.png")

                          
df["HeapDelta"] = df["HeapBefore"] - df["HeapAfterHTTP"]
plt.figure()
sns.lineplot(data=df, x="Attempt", y="HeapDelta", hue="VC_Status", marker="o")
plt.title("Heap Delta vs Attempt")
plt.xlabel("Attempt")
plt.ylabel("Heap Delta (bytes)")
plt.savefig("esp32_heap_delta_vs_attempt.png")

print("✅ All graphs saved as PNG files in current directory.")

