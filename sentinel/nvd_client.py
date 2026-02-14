
import requests
import time
import urllib.parse

class NVDClient:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        # NVD recommends sleeping 6 seconds without API key, or 0.6s with API key.
        # We'll be conservative for the PoC.
        self.delay = 6 if not api_key else 0.6 
        self.last_request_time = 0

    def _wait_for_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def lookup_cve(self, keywords, limit=5):
        """
        Search for CVEs by keyword (e.g., product name and version).
        """
        self._wait_for_rate_limit()
        
        params = {
            'keywordSearch': keywords,
            'resultsPerPage': limit
        }
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
            
        try:
            response = requests.get(self.base_url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get('vulnerabilities', [])
        except requests.exceptions.RequestException as e:
            print(f"Error querying NVD API: {e}")
            return []

    def lookup_cpe(self, product, version):
        # A more advanced implementation would use the CPE API to find the exact CPE match first,
        # then query CVEs by CPE. For PoC, keyword search is often "good enough" to demonstrate flow.
        query = f"{product} {version}"
        return self.lookup_cve(query)

if __name__ == "__main__":
    client = NVDClient()
    print("Testing NVD Lookup for 'Apache 2.4.49'...")
    results = client.lookup_cve("Apache 2.4.49")
    for item in results:
        cve = item.get('cve', {})
        print(f"{cve.get('id')} - {cve.get('descriptions', [{}])[0].get('value', 'No description')}")
