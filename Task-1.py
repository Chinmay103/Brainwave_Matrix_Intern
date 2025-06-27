import validators
import whois
import vt
from urllib.parse import urlparse
from datetime import datetime

# Replace with your actual VT key
VT_API_KEY = "bc1be74625db00bd88216307f1f4d9702a4ebc79105b62ca01f21aa7bac5d84c"

def is_url_valid(url):
    return validators.url(url)

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            today = datetime.now()
            age_days = (today - creation_date).days
            return age_days
        else:
            return None
    except Exception as e:
        print(f"[WHOIS ERROR] {e}")
        return None

def check_virustotal(api_key, url):
    try:
        client = vt.Client(api_key)
        url_id = vt.url_id(url)
        result = client.get_object(f"/urls/{url_id}")
        malicious = result.last_analysis_stats["malicious"]
        suspicious = result.last_analysis_stats["suspicious"]
        client.close()
        return malicious, suspicious
    except Exception as e:
        print(f"[VirusTotal ERROR] {e}")
        return None, None

def main():
    url = input("Enter the URL to scan: ")
    if not is_url_valid(url):
        print("Invalid URL.")
        return
    
    parsed = urlparse(url)
    domain = parsed.netloc

    # WHOIS domain age
    age = get_domain_age(domain)
    if age is not None:
        print(f"Domain age: {age} days")
        if age < 90:
            print("⚠️ Warning: domain is newly registered (under 90 days)")
    else:
        print("Could not determine domain age (WHOIS failure)")

    # VirusTotal check
    malicious, suspicious = check_virustotal(VT_API_KEY, url)
    if malicious is not None:
        print(f"VirusTotal report: {malicious} malicious detections, {suspicious} suspicious detections")
        if malicious > 0:
            print("🚨 VirusTotal flagged this as malicious.")
        elif suspicious > 0:
            print("⚠️ VirusTotal flagged this as suspicious.")
        else:
            print("✅ VirusTotal sees no problem with this link.")
    else:
        print("VirusTotal check failed.")

if __name__ == "__main__":
    main()
