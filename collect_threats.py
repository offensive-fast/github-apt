import os
import sys
import json
import requests
import feedparser
from datetime import datetime

def send_discord_webhook(webhook_url, embed_data):
    """Discord-এ Rich Embed Alert পাঠাবে।"""
    payload = {
        "username": "BD Cyber Command Intelligence",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/1014/1014293.png",
        "embeds": [embed_data]
    }
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 204:
            print("[+] Discord Advanced Alert Sent.")
        else:
            print(f"[-] Discord Failed: {response.status_code}")
    except Exception as e:
        print(f"[-] Discord Error: {e}")

def fetch_otx_data(otx_key):
    """AlienVault OTX থেকে রিয়েল-টাইম গ্লোবাল পালস নিয়ে আসবে।"""
    headers = {"X-OTX-API-KEY": otx_key} if otx_key else {}
    url = "https://otx.alienvault.com/api/v1/pulses/explore?limit=20&sort=-modified"
    try:
        res = requests.get(url, headers=headers, timeout=12)
        if res.status_code == 200:
            return res.json().get("results", [])
    except:
        print("[-] OTX Fetch Failed. Switching to fallback feeds...")
    return []

def fetch_cisa_rss():
    """CISA (Cybersecurity and Infrastructure Security Agency) থেকে লাইভ অ্যালার্ট ফিড আনবে।"""
    alerts = []
    try:
        feed = feedparser.parse("https://www.cisa.gov/cybersecurity-advisories/all.xml")
        for entry in feed.entries[:5]:
            alerts.append({
                "id": entry.get("id", entry.link),
                "name": entry.title,
                "description": entry.summary if "summary" in entry else "No summary available.",
                "tags": ["CISA", "Alert"],
                "adversaries": [],
                "targeted_countries": ["Global / Infrastructure"],
                "indicators": []
            })
    except Exception as e:
        print(f"[-] CISA RSS Fetch Error: {e}")
    return alerts

def detect_advanced_metrics(pulse):
    """ট্যাগ ও ডেসক্রিপশন অ্যানালাইসিস করে ম্যালওয়্যার ল্যাঙ্গুয়েজ এবং Severity লেভেল বের করবে।"""
    text = (pulse.get("name", "") + " " + pulse.get("description", "")).lower()
    tags = [t.lower() for t in pulse.get("tags", [])]
    
    # ১. ল্যাঙ্গুয়েজ ডিটেকশন
    lang_map = {
        "GOLANG": ["go", "golang", "go-malware"],
        "RUST": ["rust", "rust-malware", "rs"],
        "C / C++": ["c++", "cpp", "c-lang", "native"],
        "POWERSHELL": ["powershell", "ps1", "win-ps"],
        "PYTHON": ["python", "py", "keylogger.py"],
        "BASH / BSH": ["bash", "sh", "shellscript"]
    }
    detected_lang = "UNKNOWN / NATIVE BINARY"
    for lang, kws in lang_map.items():
        if any(kw in tags for kw in kws) or any(kw in text for kw in kws):
            detected_lang = lang
            break

    # ২. Severity (তীব্রতা) এবং কালার কোড নির্ধারণ
    severity = "MEDIUM"
    color = 16753920 # Orange
    
    high_keywords = ["ransomware", "apt", "critical", "zero-day", "0-day", "wiper", "government", "financial"]
    if any(kw in text for kw in high_keywords) or any(kw in tags for kw in high_keywords):
        severity = "HIGH / CRITICAL 🚨"
        color = 15158332 # Red
        
    return detected_lang, severity, color

def enrich_ip_intelligence(ip, ipinfo_key):
    """IP এনরিচমেন্ট: অ্যাটাকারের ISP, ASN এবং স্প্যাম/বটনেট স্ট্যাটাস চেক করবে।"""
    if not ip:
        return "Unknown ISP", "Unknown Country"
    
    url = f"https://ipinfo.io/{ip}?token={ipinfo_key}" if ipinfo_key else f"https://ipinfo.io/{ip}/json"
    try:
        res = requests.get(url, timeout=5).json()
        org = res.get("org", "Unknown ASN/ISP") # এটি ASN এবং ISP এর নাম দেয়
        country = res.get("country", "Unknown")
        return org, country
    except:
        return "Unknown ISP", "Unknown Country"

def extract_iocs(pulse):
    """পালস থেকে সুনির্দিষ্ট আইওসি এক্সট্রাক্ট করা।"""
    ips, malwares, cves = [], [], []
    for ind in pulse.get("indicators", []):
        itype = ind.get("type")
        val = ind.get("indicator")
        if itype in ["IPv4", "IPv6"]: ips.append(val)
        elif itype in ["FileHash-SHA256", "FileHash-MD5"]: malwares.append(val[:15] + "...")
        elif itype == "CVE": cves.append(val)
    return list(set(ips))[:5], list(set(malwares))[:5], list(set(cves))[:5]

def main():
    otx_key = os.getenv("OTX_API_KEY")
    discord_webhook = os.getenv("DISCORD_WEBHOOK")
    ipinfo_key = os.getenv("IPINFO_KEY")

    if not discord_webhook:
        print("[-] DISCORD_WEBHOOK missing.")
        sys.exit(1)

    # ওটিএক্স এবং সিআইএসএ ২ সোর্স থেকেই ডেটা নেওয়া (মাল্টি-ফিড)
    print("[*] Gathering Multi-Feed Threat Intelligence...")
    all_pulses = fetch_otx_data(otx_key) + fetch_cisa_rss()

    processed_file = "docs/live_threats.json"
    existing_ids = []
    if os.path.exists(processed_file):
        try:
            with open(processed_file, "r") as f:
                existing_ids = [item["id"] for item in json.load(f) if "id" in item]
        except: pass

    new_threats = []

    for pulse in all_pulses:
        pid = pulse.get("id")
        if pid in existing_ids:
            continue

        # অ্যাডভান্সড মেট্রিক্স এক্সট্রাকশন
        lang, severity, embed_color = detect_advanced_metrics(pulse)
        ips, malwares, cves = extract_iocs(pulse)
        
        # আইপি এনরিচমেন্ট
        primary_ip = ips[0] if ips else None
        isp_asn, country = enrich_ip_intelligence(primary_ip, ipinfo_key)

        apt_group = pulse.get("adversaries", [None])[0] if pulse.get("adversaries") else "Unknown / Not Defined"
        victim = ", ".join(pulse.get("targeted_countries", [])) or "Global / Multiple Infrastructure"

        # ডিস্কোর্ড অ্যাডভান্সড এম্বেড মেসেজ
        embed = {
            "title": f"📢 ADVANCED INTEL: {pulse.get('name')}",
            "description": f"**Description:** {pulse.get('description', 'No details specified.')[:300]}...",
            "color": embed_color,
            "fields": [
                {"name": "🔥 Severity Level", "value": f"`{severity}`", "inline": True},
                {"name": "👤 Threat Actor / APT", "value": f"**{apt_group}**", "inline": True},
                {"name": "🛠️ Tech / Language", "value": f"`{lang}`", "inline": True},
                {"name": "🎯 Targeted Sectors", "value": str(victim), "inline": True},
                {"name": "🏢 Attacker ASN / ISP", "value": f"`{isp_asn}` ({country})", "inline": False},
                {"name": "💻 Exploited CVE(s)", "value": ", ".join(cves) if cves else "None Identified", "inline": True},
                {"name": "🌐 Active C2 / Attacking IPs", "value": ", ".join(ips) if ips else "None Identified", "inline": False},
                {"name": "🦠 Malware Hashes / IOCs", "value": ", ".join(malwares) if malwares else "None Identified", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": f"Source Identifier: {pid} | Advanced Threat Hunting Module"}
        }

        send_discord_webhook(discord_webhook, embed)
        
        new_threats.append({
            "id": pid, "name": pulse.get("name"), "apt_group": apt_group,
            "severity": severity, "language": lang, "ips": ips, "isp": isp_asn,
            "location": country, "malware": malwares, "cve": cves, "victim": victim,
            "date": datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        })

    if new_threats:
        os.makedirs("docs", exist_ok=True)
        try:
            with open(processed_file, "r") as f: current_db = json.load(f)
        except: current_db = []
        
        with open(processed_file, "w") as f:
            json.dump((new_threats + current_db)[:100], f, indent=4)
        print(f"[+] Successfully integrated {len(new_threats)} advanced threats.")

if __name__ == "__main__":
    main()
