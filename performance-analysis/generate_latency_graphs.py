#!/usr/bin/env python3
import argparse
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

parser = argparse.ArgumentParser(description="Generate latency graphs from a CSV log")
parser.add_argument("csv_file", nargs="?", help="Path to CSV log file")
args = parser.parse_args()

csv_file = args.csv_file or input("CSV file to analyze: ").strip()

output_dir = "latency_graphs"
os.makedirs(output_dir, exist_ok=True)

if not csv_file:
    raise SystemExit("No CSV file specified")

df = pd.read_csv(csv_file)

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["payload_size"] = pd.to_numeric(df["payload_size"], errors="coerce")

latency_cols = [
    "did_time", "vc_time", "vp_time", "verify_time", "revoke_time", "verify_revoked_time"
]

for col in latency_cols:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df = df.dropna(subset=latency_cols + ["payload_size"])

def remove_iqr_outliers(data, cols):
    mask = np.ones(len(data), dtype=bool)
    for col in cols:
        Q1 = data[col].quantile(0.25)
        Q3 = data[col].quantile(0.75)
        IQR = Q3 - Q1
        col_mask = (data[col] >= (Q1 - 1.5 * IQR)) & (data[col] <= (Q3 + 1.5 * IQR))
        mask &= col_mask
    return data[mask]

df_clean = remove_iqr_outliers(df, latency_cols)

plt.figure(figsize=(10, 6))
sns.boxplot(data=df_clean[latency_cols])
plt.title("Latency Distribution per Step")
plt.ylabel("Time (seconds)")
plt.grid(True)
plt.tight_layout()
plt.savefig(f"{output_dir}/latency_boxplot.png")
plt.close()

plt.figure(figsize=(12, 6))
df_melted = df_clean.melt(id_vars="payload_size", value_vars=latency_cols, var_name="step", value_name="latency")
sns.boxplot(x="step", y="latency", hue="payload_size", data=df_melted)
plt.title("Latency Distribution by Payload Size and Step")
plt.ylabel("Time (seconds)")
plt.grid(True)
plt.tight_layout()
plt.savefig(f"{output_dir}/latency_boxplot_by_payload.png")
plt.close()

grouped = df_clean.groupby("payload_size")[latency_cols].mean().sort_index()
plt.figure(figsize=(12, 6))
for col in latency_cols:
    plt.plot(grouped.index, grouped[col], marker="o", label=col)
plt.title("Mean Latency per Step by Payload Size")
plt.xlabel("Payload Size")
plt.ylabel("Time (seconds)")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(f"{output_dir}/latency_line_chart_by_payload.png")
plt.close()

percentiles = [50, 75, 90]
for step in latency_cols:
    plt.figure(figsize=(10, 6))

                                           
    zscores = (df_clean[step] - df_clean[step].mean()) / df_clean[step].std()
    df_step = df_clean[zscores.abs() < 3]

                                         
    pct_df = df_step.groupby("payload_size")[step].quantile([p/100 for p in percentiles]).unstack()
    pct_df.columns = [f"{p}th" for p in percentiles]
    pct_df = pct_df.sort_index()

    for col in pct_df.columns:
        plt.plot(pct_df.index, pct_df[col], marker="o", label=col)

    plt.title(f"{step} Latency Percentiles by Payload Size")
    plt.xlabel("Payload Size")
    plt.ylabel("Latency (seconds)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{output_dir}/percentiles_{step}.png")
    plt.close()
