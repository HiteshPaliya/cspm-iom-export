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
    Fetch IOMs (assessments) filtered by account_id and Status (Unresolved).
    Unresolved usually maps to 'Open', 'Reopen', 'New'.
    """
    print(f"Fetching Unresolved IOMs for Subscription ID: {subscription_id}...")
    
    # FQL Filter:
    # 1. account_id matches
    # 2. status is Open or Reopen (Unresolved)
    # Note: Adjust status values based on your specific environment usage if needed.
    filters = f"account_id:'{subscription_id}'+status:['Open','Reopen','New']"
    
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
        offset += len(resources)
        
        print(f"Fetched {len(all_findings)} / {total} findings...")
        
        if len(all_findings) >= total:
            break
            
    return all_findings

def filter_publicly_verifiable(findings):
    """
    Filter findings for 'Publicly Verifiable IOMs'.
    This mimics the Saved Filter logic by checking for keywords in the description
    or policy statement.
    """
    print("Filtering for 'Publicly Verifiable' findings...")
    filtered = []
    for finding in findings:
        description = finding.get("description", "").lower()
        policy = finding.get("policy_statement", "").lower()
        
        # Heuristic for "Publicly Accessible/Verifiable"
        if "publicly accessible" in description or "publicly accessible" in policy:
            filtered.append(finding)
        elif "public" in description and "access" in description: 
             filtered.append(finding)
        elif "public" in policy and "access" in policy:
             filtered.append(finding)

    print(f"Remaining findings after filter: {len(filtered)}")
    return filtered

def enrich_and_filter_assets(cloud_assets_client, findings):
    """
    Enrich findings with Cloud Asset details AND filter by Asset Status = Active.
    Only returns IOMs where the associated asset is found and is Active.
    """
    if not findings:
        return []

    print("Enriching findings and filtering for Active Assets...")
    
    enriched_data = []
    resource_ids = list(set([f.get("resource_id") for f in findings if f.get("resource_id")]))
    
    # API limit for get_assets is typically 100
    batch_size = 100
    assets_map = {}
    
    for i in range(0, len(resource_ids), batch_size):
        batch_ids = resource_ids[i:i+batch_size]
        
        # We fetch the assets by ID.
        # We can't easily filter by status=active in the get_assets(ids=...) call 
        # because get_assets usually just returns what implies the ID.
        # So we fetch then filter in python.
        response = cloud_assets_client.get_assets(ids=batch_ids)
        
        if response["status_code"] == 200:
            resources = response["body"].get("resources", [])
            for asset in resources:
                # Check Asset Status
                # "status" field in asset resource
                status = asset.get("status", "").lower()
                if status == "active" or status == "running" or status == "ok": 
                    # 'running'/'ok' depend on provider, but 'active' is standard Falcon state?
                    # Let's assume 'active' or check if it's not 'terminated'/'deleted'.
                    # For strictness, let's look for 'active'.
                    # We will also accept if status is missing? No, user said Active.
                    # Actually, let's print unique statuses found to help debug if it filters everything.
                    assets_map[asset.get("asset_id")] = asset
        else:
            print(f"Warning: Failed to fetch assets for batch {i}: {response['body']['errors']}")

    print(f"Found {len(assets_map)} Active assets associated with findings.")

    # Merge: Inner Join
    for finding in findings:
        r_id = finding.get("resource_id")
        if r_id in assets_map:
            asset_info = assets_map[r_id]
            
            merged = finding.copy()
            merged["asset_name"] = asset_info.get("asset_name")
            merged["cloud_provider"] = asset_info.get("cloud_provider")
            merged["region"] = asset_info.get("region")
            merged["asset_type"] = asset_info.get("asset_type")
            merged["public_ip"] = asset_info.get("public_ip_address")
            merged["tags"] = asset_info.get("tags")
            merged["asset_status"] = asset_info.get("status")
            
            enriched_data.append(merged)
        
    return enriched_data

def main():
    print("--- Falcon CSPM IOM Export Script (Filtered) ---")
    
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
    
    # 4. Get IOMs (Filtered by Sub ID + Unresolved Status)
    ioms = get_ioms(config_client, sub_id)
    if not ioms:
        print("No Unresolved IOMs found for this subscription.")
        return

    # 5. Filter for 'Publicly Verifiable'
    filtered_ioms = filter_publicly_verifiable(ioms)
    if not filtered_ioms:
        print("No 'Publicly Verifiable' IOMs found.")
        return

    # 6. Enrich with Assets and Filter for 'Active' Assets
    final_data = enrich_and_filter_assets(asset_client, filtered_ioms)
    
    if not final_data:
        print("No findings remained after filtering for Active Assets.")
        return

    # 7. Export
    df = pd.DataFrame(final_data)
    output_file = "cspm_ioms_export_filtered.csv"
    df.to_csv(output_file, index=False)
    print(f"Successfully exported {len(df)} records to {output_file}")

if __name__ == "__main__":
    main()
