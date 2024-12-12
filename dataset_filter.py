import pandas as pd

# Load the dataset
file_path = "malicious_phish_all.csv"  # Replace with the path to your dataset
data = pd.read_csv(file_path)

# Check the class distribution
print(data['label'].value_counts())

# Filter classes to include only the desired ones
desired_classes = ['benign', 'defacement', 'phishing', 'malware']
filtered_data = data[data['label'].isin(desired_classes)]

# Perform stratified sampling to get 333 samples per class
sampled_data = filtered_data.groupby('label').apply(lambda x: x.sample(n=500, random_state=42))

# Drop the added group keys
sampled_data = sampled_data.reset_index(drop=True)

# Verify the class distribution in the subset
print(sampled_data['label'].value_counts())

# Save the balanced subset to a new CSV file
output_file = "output2.csv"  # Replace with your desired output file name
sampled_data.to_csv(output_file, index=False)

print(f"Balanced subset saved to {output_file}")
