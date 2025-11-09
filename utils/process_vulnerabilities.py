import json
import os
from collections import defaultdict

# --- Configuration ---
SLUG_INPUT_FILE = 'top_10k_plugin_slugs.txt'
DB_INPUT_FILE = 'wordfence_db.json'
VULN_OUTPUT_FILE = 'plugin_vulnerabilities.json'

def process_vulnerabilities():
    """
    Cross-references the slug list against the downloaded Wordfence database
    to build the final vulnerability mapping.
    """
    
    # --- 1. Load Input Files ---
    if not os.path.exists(SLUG_INPUT_FILE):
        print(f"Error: Slug file not found: {SLUG_INPUT_FILE}")
        return

    if not os.path.exists(DB_INPUT_FILE):
        print(f"Error: Wordfence DB not found: {DB_INPUT_FILE}")
        print(f"Please run download_wordfence_db.py first.")
        return

    print(f"Loading slugs from {SLUG_INPUT_FILE}...")
    with open(SLUG_INPUT_FILE, 'r') as f:
        # Use a set for very fast lookups
        slug_set = set(line.strip() for line in f if line.strip())
    print(f"Loaded {len(slug_set)} unique plugin slugs.")

    print(f"Loading Wordfence database from {DB_INPUT_FILE}...")
    try:
        with open(DB_INPUT_FILE, 'r') as f:
            wordfence_db = json.load(f)
    except Exception as e:
        print(f"Error loading {DB_INPUT_FILE}: {e}")
        return
    
    print(f"Loaded {len(wordfence_db)} total vulnerabilities.")

    # --- 2. Build the Vulnerability Map ---
    # We build a map of {slug -> [list of vulnerabilities]}
    # This is more efficient than looping 10,000 times.
    
    print("Building plugin-to-vulnerability map...")
    plugin_to_vulns_map = defaultdict(list)
    
    # The Wordfence DB is a dict: {uuid: vulnerability_object}
    for vuln_uuid, vuln_data in wordfence_db.items():
        if 'software' not in vuln_data:
            continue
            
        # Check all software this vulnerability affects
        for software_item in vuln_data.get('software', []):
            slug = software_item.get('slug')
            
            # If this is a plugin and it's in our 10k list...
            if software_item.get('type') == 'plugin' and slug in slug_set:
                
                # --- FIX starts here ---
                # Original line 64 had the bug.
                # We must check if .get('cwe') returns None before trying to call .get('name') on it.
                cwe_data = vuln_data.get('cwe')
                vuln_type = cwe_data.get('name', 'Unknown') if cwe_data else 'Unknown'
                # --- FIX ends here ---

                # Extract the key data you need
                processed_vuln = {
                    "cve": vuln_data.get('cve'),
                    "type": vuln_type, # Use the safe variable from above
                    "title": vuln_data.get('title', 'No Title'),
                    "references": vuln_data.get('references', []),
                    "wordfence_uuid": vuln_uuid
                }
                
                # ...add this vulnerability to that slug's list
                plugin_to_vulns_map[slug].append(processed_vuln)

    # --- FIX for print statement ---
    # Added the 'f' to make it a proper f-string
    print(f"Map built. Found vulnerabilities for {len(plugin_to_vulns_map)} plugins.")

    # --- 3. Create Final Output File ---
    # We must create an entry for ALL 10k slugs, even if they have
    # no vulnerabilities (in which case we'll use `None`).
    
    final_output_data = {}
    for slug in slug_set:
        # Get the list of vulns, or 'None' if the slug wasn't found in the map
        final_output_data[slug] = plugin_to_vulns_map.get(slug, None)

    # --- 4. Save to File ---
    print(f"Saving final data to {VULN_OUTPUT_FILE}...")
    try:
        with open(VULN_OUTPUT_FILE, 'w') as f:
            json.dump(final_output_data, f, indent=2)
        print("✅ SUCCESS: All processing complete.")
        print(f"Final dataset is saved in {VULN_OUTPUT_FILE}")
    except IOError as e:
        print(f"❌ ERROR: Could not write to output file: {e}")

if __name__ == "__main__":
    process_vulnerabilities()