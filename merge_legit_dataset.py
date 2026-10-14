import pandas as pd

# Load existing dataset
df_old = pd.read_csv("data/5.urldata.csv")  # <-- your folder is named data

# Load new legitimate URLs
df_new = pd.read_csv("legitimate_sites.csv")

# Combine datasets
df_combined = pd.concat([df_old, df_new], ignore_index=True)

# Shuffle
df_combined = df_combined.sample(frac=1, random_state=42)

# Save updated dataset
df_combined.to_csv("data/5.urldata_updated.csv", index=False)
print("Updated dataset saved as urldata_updated.csv")