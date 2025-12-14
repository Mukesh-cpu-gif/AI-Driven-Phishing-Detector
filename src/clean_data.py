import pandas as pd
import os

# --- CONFIGURATION ---
INPUT_FILE = "Phishing_Email.csv"  # Make sure this matches your downloaded file name
OUTPUT_FILE = "cleaned_phishing_data.csv"

def clean_dataset():
    # 1. Load Data
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: Could not find {INPUT_FILE}. Please move it to this folder.")
        return

    print("Loading data...")
    # 'encoding_errors' helps skip bad characters
    df = pd.read_csv(INPUT_FILE, on_bad_lines='skip') 
    
    print(f"Original Count: {len(df)}")

    # 2. Basic Cleaning
    # Drop rows where 'Email Text' or 'Email Type' is missing
    df.dropna(subset=['Email Text', 'Email Type'], inplace=True)
    
    # Drop exact duplicates
    df.drop_duplicates(inplace=True)
    
    print(f"Count after removing duplicates/errors: {len(df)}")

    # 3. Class Balancing (The "Perfect" Split)
    # We want exactly 50% Phishing and 50% Safe
    safe_emails = df[df['Email Type'] == 'Safe Email']
    phish_emails = df[df['Email Type'] == 'Phishing Email']
    
    print(f"   - Safe Emails: {len(safe_emails)}")
    print(f"   - Phishing Emails: {len(phish_emails)}")
    
    # Find which one is smaller (usually Phishing)
    min_count = min(len(safe_emails), len(phish_emails))
    
    print(f"⚖️  Balancing dataset to {min_count} emails of each type...")
    
    # Randomly sample the larger group to match the smaller group
    df_balanced = pd.concat([
        safe_emails.sample(n=min_count, random_state=42),
        phish_emails.sample(n=min_count, random_state=42)
    ])
    
    # Shuffle the rows so they aren't in order
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    # 4. Save
    df_balanced.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ Success! Saved perfect dataset to: {OUTPUT_FILE}")
    print(f"Final Total Rows: {len(df_balanced)}")

if __name__ == "__main__":
    # You might need to install pandas first: 
    # py -m pip install pandas
    clean_dataset()