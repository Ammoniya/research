import requests
import json
import os
from pathlib import Path
import sys

# Import centralized data paths
sys.path.insert(0, str(Path(__file__).parent.parent))
from data_paths import INPUT_WORDFENCE_DB

# --- Configuration ---
# This is the public, key-less API endpoint for the Wordfence Production feed
API_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
OUTPUT_FILE = str(INPUT_WORDFENCE_DB)
REQUEST_TIMEOUT = 30  # This can be a large download

def download_database():
    """
    Downloads the entire Wordfence production vulnerability feed.
    This is a single, large JSON file.
    """
    if os.path.exists(OUTPUT_FILE):
        print(f"Found existing database file: {OUTPUT_FILE}")
        print("To re-download, please delete the file first.")
        return
        
    print(f"🚀 Starting download of Wordfence vulnerability database...")
    print(f"   From: {API_URL}")
    print(f"   To:   {OUTPUT_FILE}")
    print("This may take a moment...")

    try:
        response = requests.get(API_URL, timeout=REQUEST_TIMEOUT)
        
        # Check for HTTP errors
        response.raise_for_status()
        
        # The response is the raw JSON data
        data = response.json()
        
        # Save the data
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"\n✅ SUCCESS: Database saved to {OUTPUT_FILE}")
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR: Failed to download database: {e}")
    except json.JSONDecodeError:
        print(f"\n❌ ERROR: Failed to decode JSON from Wordfence. Response was not valid JSON.")
    except IOError as e:
        print(f"\n❌ ERROR: Could not write to file {OUTPUT_FILE}: {e}")

if __name__ == "__main__":
    download_database()