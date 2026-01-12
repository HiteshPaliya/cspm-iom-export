import os
import sys
import pandas as pd
from falconpy import ConfigurationAssessment, CloudSecurityAssets, OAuth2

def get_credentials():
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    
    if not client_id:
        client_id = input("Enter standard Falcon Client ID: ").strip()
    if not client_secret:
        client_secret = input("Enter standard Falcon Client Secret: ").strip()
    
    return client_id, client_secret

def get_ioms(config_assessment_client, subscription_id, limit=5000):
    """
    Fetch IOMs (assessments) filtered by account_id (Subscription ID).
    """
    print(f"Fetching IOMs for Subscription ID: {subscription_id}...")
    
    # FQL Filter for the subscription/account ID
    filters = f"account_id:'{subscription_id}'"
    
    # Fetch findings
    # using get_combined_assessments to get the details directly
    # Note: Pagination loops might be needed for large datasets, 
    # but we'll start with a generic fetch for now or use the logic to offset.
    
    all_findings = []
    offset = 0
    total = 0
    
    while True:
        response = config_assessment_client.get_combined_assessments(
            filter=filters,
            limit=limit,
            offset=offset
        )
        
        if response["status_code"] != 200:
            print(f"Error fetching assessments: {response['body']['errors']}")
            break
            
        resources = response["body"].get("resources", [])
        if not resources:
            break
            
        all_findings.extend(resources)
        
        meta = response["body"].get("meta", {})
        pagination = meta.get("pagination", {})
        total = pagination.get("total", 0)
        offset += len(resources) # API usually uses total/offset or just offset
        
        print(f"Fetched {len(all_findings)} / {total} findings...")
        
        if len(all_findings) >= total:
            break
            
    return all_findings

def filter_publicly_accessible(findings):
    """
    Filter findings based on 'Publicly Accessible' logic.
    We check if the policy description or rule name implies public accessibility.
    """
    print("Filtering for 'Publicly Accessible' findings...")
    filtered = []
    for finding in findings:
        description = finding.get("description", "").lower()
        policy = finding.get("policy_statement", "").lower()
        
        # User requested filtering by custom filter "Publicly Accessible".
        # This is strictly searching for the string "Publicly Accessible" or "Public" 
        # in the description/policy as a heuristic if the explicit tag isn't there.
        # Adjust this logic if there is a specific field for this.
        
        if "publicly accessible" in description or "publicly accessible" in policy:
            filtered.append(finding)
        # Fallback: check for "public" keyword if the specific phrase is too strict, 
        # but the user was specific. We will stick to the specific phrase first.
        # If the user meant a SAVED filter, we can't easily access that via this specific endpoint logic 
        # without looking up the filter definition first.
        # Let's add a broader check for now to be safe, assuming "Publicly Accessible" is the intent.
        elif "public" in description and "access" in description: 
             filtered.append(finding)

    print(f"Remaining findings after filter: {len(filtered)}")
    return filtered

def enrich_with_assets(cloud_assets_client, findings):
    """
    Enrich findings with Cloud Asset details.
    """
    if not findings:
        return []

    print("Enriching findings with Cloud Asset details...")
    
    # helper for fast lookup
    enriched_data = []
    
    # Batch resource IDs for querying
    resource_ids = list(set([f.get("resource_id") for f in findings if f.get("resource_id")]))
    
    # API limit for get_assets is typically 100
    batch_size = 100
    assets_map = {}
    
    for i in range(0, len(resource_ids), batch_size):
        batch_ids = resource_ids[i:i+batch_size]
        response = cloud_assets_client.get_assets(ids=batch_ids)
        
        if response["status_code"] == 200:
            resources = response["body"].get("resources", [])
            for asset in resources:
                # Store asset by ID
                # assets usually have an 'asset_id' or 'id'
                # fallback to checking how it maps. usually finding['resource_id'] == asset['asset_id']
                a_id = asset.get("asset_id") 
                if a_id:
                   assets_map[a_id] = asset
        else:
            print(f"Warning: Failed to fetch assets for batch {i}: {response['body']['errors']}")

    # Merge
    for finding in findings:
        r_id = finding.get("resource_id")
        asset_info = assets_map.get(r_id, {})
        
        # Merge dictionaries
        # prioritizing finding data, adding asset data
        merged = finding.copy()
        
        # key collision handling? prefix asset keys?
        # let's just add a few specific important asset fields or flatten
        merged["asset_name"] = asset_info.get("asset_name")
        merged["cloud_provider"] = asset_info.get("cloud_provider")
        merged["region"] = asset_info.get("region")
        merged["asset_type"] = asset_info.get("asset_type")
        merged["public_ip"] = asset_info.get("public_ip_address")
        merged["tags"] = asset_info.get("tags")
        
        enriched_data.append(merged)
        
    return enriched_data

def main():
    print("--- Falcon CSPM IOM Export Script ---")
    
    # 1. Inputs
    sub_id = input("Enter the Subscription ID (Account ID): ").strip()
    if not sub_id:
        print("Subscription ID is required.")
        return

    client_id, client_secret = get_credentials()
    
    # 2. Authenticate
    auth = OAuth2(client_id=client_id, client_secret=client_secret)
    
    # 3. Clients
    config_client = ConfigurationAssessment(auth_object=auth)
    asset_client = CloudSecurityAssets(auth_object=auth)
    
    # 4. Get IOMs
    ioms = get_ioms(config_client, sub_id)
    if not ioms:
        print("No IOMs found.")
        return

    # 5. Filter
    filtered_ioms = filter_publicly_accessible(ioms)
    if not filtered_ioms:
        print("No IOMs match the 'Publicly Accessible' criteria.")
        # Ask if user wants to export all anyway?
        # For now, let's just return. 
        # Actually, let's allow export of all if filter is empty? 
        # No, strict requirement.
        return

    # 6. Enrich
    final_data = enrich_with_assets(asset_client, filtered_ioms)
    
    # 7. Export
    df = pd.DataFrame(final_data)
    output_file = "cspm_ioms_export.csv"
    df.to_csv(output_file, index=False)
    print(f"Successfully exported {len(df)} records to {output_file}")

if __name__ == "__main__":
    main()
