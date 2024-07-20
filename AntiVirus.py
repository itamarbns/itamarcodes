import os
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

API_KEY = '25863e5e5775b64649208a93bacdfbe5ffe05000b5309edf6a3a034a121dca77'
MAX_WORKERS = 4  # Number of threads to use for concurrent uploads

def scandirectory(directory):
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        print(filepath)
        if os.path.isdir(filepath):
            scandirectory(filepath)
        else:
            yield filepath

def scan_file(filepath):
    url = "https://www.virustotal.com/api/v3/files"
    
    with open(filepath, "rb") as file:
        files = {"file": (os.path.basename(filepath), file)}
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        
        response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            scan_id = response.json()['data']['id']
            print(f"Scan ID: {scan_id} for file {filepath}")
            return scan_id, filepath
        else:
            print(f"Failed to scan file {filepath}: {response.status_code} - {response.text}")
            return None, filepath

def check_scan_results(scan_id, filepath):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis = response.json()
            status = analysis['data']['attributes']['status']
            if status == 'completed':
                stats = analysis['data']['attributes']['stats']
                malicious = stats['malicious']
                if malicious > 0:
                    print(f"{filepath} is malicious.")
                else:
                    print(f"{filepath} is clean.")
                break
            else:
                print(f"Scan for {filepath} is still in progress...")
                time.sleep(10)  # Wait before retrying
        else:
            print(f"Failed to get scan results for {filepath}: {response.status_code} - {response.text}")
            break

def main(directory):
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(scan_file, filepath): filepath for filepath in scandirectory(directory)}
        
        for future in as_completed(future_to_file):
            scan_id, filepath = future.result()
            if scan_id:
                check_scan_results(scan_id, filepath)

if __name__ == "__main__":
    directory = "D:\PolyBridge\Poly.Bridge.3.v1.2.5\MonoBleedingEdge\EmbedRuntime"
    main(directory)
