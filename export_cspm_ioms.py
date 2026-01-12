import os
import sys
import pandas as pd
import concurrent.futures
from falconpy import ConfigurationAssessment, CloudSecurityAssets, SavedFilters, OAuth2

def get_credentials():
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    
    if not client_id:
        client_id = input("Enter standard Falcon Client ID: ").strip()
    if not client_secret:
        client_secret = input("Enter standard Falcon Client Secret: ").strip()
    
    return client_id, client_secret

def get_saved_filter_fql(auth_object, filter_name):
    """
    Retrieves the FQL string for a named saved filter using the SavedFilters service.
    """
    print(f"Looking up Saved Filter: '{filter_name}'...")
    falcon_filters = SavedFilters(auth_object=auth_object)
    
    # Query for the filter by name
    res = falcon_filters.query_saved_filters(filter=f"name:'{filter_name}'")
    
    if res["status_code"] == 200:
        resources = res["body"].get("resources", [])
        if resources:
             filter_id = resources[0]
             # Get details
             detail = falcon_filters.get_saved_filters(ids=filter_id)
             if detail["status_code"] == 200 and detail["body"].get("resources"):
                 fql = detail["body"]["resources"][0].get("filter", "")
                 print(f"Found Saved Filter FQL: {fql}")
                 return fql
    
    print(f"Warning: Saved filter '{filter_name}' not found. Using fallback heuristic.")
    return None

def get_ioms(config_assessment_client, subscription_id, saved_filter_fql=None, limit=5000):
    """
    Fetch IOMs (assessments) filtered by account_id and Status (Unresolved).
    Unresolved usually maps to 'Open', 'Reopen', 'New'.
    """
    print(f"Fetching Unresolved IOMs for Subscription ID: {subscription_id}...")
    
    # Base FQL
    base_filter = f"account_id:'{subscription_id}'+status:['Open','Reopen','New']"
    
    # Combine with Saved Filter FQL if exists
    if saved_filter_fql:
        # Wrap in parens to ensure precedence
        filters = f"({base_filter})+({saved_filter_fql})"
    else:
        filters = base_filter
        
    print(f"Using FQL: {filters}")
    
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

def fallback_filter_publicly_verifiable(findings):
    """
    Fallback: Filter findings for 'Publicly Verifiable IOMs' using text heuristics
    if the Saved Filter FQL lookup failed.
    """
    print("Applying fallback filtering for 'Publicly Verifiable' findings...")
    filtered = []
    for finding in findings:
        description = finding.get("description", "").lower()
        policy = finding.get("policy_statement", "").lower()
        
        if "publicly accessible" in description or "publicly accessible" in policy:
            filtered.append(finding)
        elif "public" in description and "access" in description: 
             filtered.append(finding)
        elif "public" in policy and "access" in policy:
             filtered.append(finding)

    print(f"Remaining findings after fallback filter: {len(filtered)}")
    return filtered

def fetch_asset_batch(cloud_assets_client, batch_ids):
    """
    Helper function to fetch a single batch of assets.
    """
    response = cloud_assets_client.get_assets(ids=batch_ids)
    if response["status_code"] == 200:
        return response["body"].get("resources", [])
    else:
        print(f"Warning: Failed to fetch assets for batch: {response['body']['errors']}")
        return []

def enrich_and_filter_assets(cloud_assets_client, findings):
    """
    Enrich findings with Cloud Asset details AND filter by Asset Status = Active.
    Uses ThreadPoolExecutor for concurrent batch fetching.
    """
    if not findings:
        return []

    print("Enriching findings and filtering for Active Assets (Concurrent)...")
    
    enriched_data = []
    resource_ids = list(set([f.get("resource_id") for f in findings if f.get("resource_id")]))
    
    batch_size = 100
    assets_map = {}
    batches = [resource_ids[i:i+batch_size] for i in range(0, len(resource_ids), batch_size)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_batch = {
            executor.submit(fetch_asset_batch, cloud_assets_client, batch): batch 
            for batch in batches
        }
        
        for future in concurrent.futures.as_completed(future_to_batch):
            fetched_assets = future.result()
            for asset in fetched_assets:
                status = asset.get("status", "").lower()
                if status == "active" or status == "running" or status == "ok":
                    assets_map[asset.get("asset_id")] = asset

    print(f"Found {len(assets_map)} Active assets associated with findings.")

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
    print("--- Falcon CSPM IOM Export Script (Filtered & Optimized) ---")
    
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
    
    # 4. Lookup Saved Filter
    saved_filter_name = "Publicly Verifiable IOMs"
    saved_fql = get_saved_filter_fql(auth, saved_filter_name)
    
    # 5. Get IOMs
    ioms = get_ioms(config_client, sub_id, saved_filter_fql=saved_fql)
    if not ioms:
        print("No matches found.")
        return

    # 6. Fallback Filter (only if Saved Filter FQL was NOT found)
    if not saved_fql:
        ioms = fallback_filter_publicly_verifiable(ioms)
        if not ioms:
            print("No 'Publicly Verifiable' IOMs found after fallback filtering.")
            return

    # 7. Enrich and Asset Status Filter
    final_data = enrich_and_filter_assets(asset_client, ioms)
    
    if not final_data:
        print("No findings remained after filtering for Active Assets.")
        return

    # 8. Export
    df = pd.DataFrame(final_data)
    output_file = "cspm_ioms_export_filtered.csv"
    df.to_csv(output_file, index=False)
    print(f"Successfully exported {len(df)} records to {output_file}")

if __name__ == "__main__":
    main()
