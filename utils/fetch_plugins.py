import requests
import json
import time
from pathlib import Path
import sys

# Import centralized data paths
sys.path.insert(0, str(Path(__file__).parent.parent))
from data_paths import INPUT_PLUGIN_LIST

# --- Configuration ---
API_URL = "https://api.wordpress.org/plugins/info/1.1/"
TOTAL_PAGES = 100  # 100 pages * 100 per_page = 10,000 plugins
PER_PAGE = 100
OUTPUT_FILE = str(INPUT_PLUGIN_LIST)

# --- Script ---
all_plugin_slugs = []

print(f"🚀 Starting fetch for top {TOTAL_PAGES * PER_PAGE} popular plugins...")
print(f"Data will be saved to {OUTPUT_FILE}")

for page in range(1, TOTAL_PAGES + 1):
    # These are the parameters for the API call
    # The keys 'request[browse]', 'request[per_page]', etc.
    # are exactly what the WordPress API expects.
    params = {
        'action': 'query_plugins',
        'request[browse]': 'popular',
        'request[per_page]': PER_PAGE,
        'request[page]': page
    }
    
    try:
        print(f"Fetching page {page}/{TOTAL_PAGES}...")
        
        # Make the API request
        response = requests.get(API_URL, params=params, timeout=10)
        
        # Check for HTTP errors (like 404, 500)
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        
        # 'plugins' is the key holding the list of plugin objects
        if 'plugins' in data and data['plugins']:
            # Extract the 'slug' from each plugin object
            for plugin in data['plugins']:
                if 'slug' in plugin:
                    all_plugin_slugs.append(plugin['slug'])
        else:
            # This might happen if we ask for more pages than exist
            print(f"Warning: No 'plugins' data found on page {page}. Stopping early.")
            break
            
    except requests.exceptions.RequestException as e:
        print(f"Error on page {page}: {e}")
        print("Skipping this page and continuing...")
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON response on page {page}.")
        print("Skipping this page and continuing...")
        
    # Be polite to the API: wait half a second between requests
    time.sleep(0.5)

print("\n--- Fetching Complete ---")
print(f"Total slugs collected: {len(all_plugin_slugs)}")

# --- Save to File ---
try:
    with open(OUTPUT_FILE, 'w') as f:
        for slug in all_plugin_slugs:
            f.write(f"{slug}\n")
    
    print(f"✅ Successfully saved {len(all_plugin_slugs)} slugs to {OUTPUT_FILE}")
    
    # Show a small sample
    if all_plugin_slugs:
        print("\nSample (first 10 slugs):")
        for slug in all_plugin_slugs[:10]:
            print(f"  - {slug}")
            
except IOError as e:
    print(f"Error: Could not write to file {OUTPUT_FILE}: {e}")