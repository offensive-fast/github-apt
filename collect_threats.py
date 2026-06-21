import os
import sys
import json
import requests
from datetime import datetime

def send_discord_webhook(webhook_url, embed_data):
    """Discord-এ সুন্দর একটি Rich Embed Alert নোটিফিকেশন পাঠাবে।"""
    payload = {
        "username": "BD Bangladesh Threat Hunter",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/1014/1014293.png",
        "embeds": [embed_data]
    }
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 204:
            print("[+] Discord Alert Sent Successfully.")
        else:
            print(f"[-] Discord Failed: {response.status_code}")
    except Exception as e:
        print(f"[-] Discord Network Error: {e}")

def fetch_real_threat_data(otx_key):
    """AlienVault OTX এবং পাবলিক APT ফিড থেকে লাইভ রিয়েল অ্যাটাক ডেটা আনবে।"""
    headers = {"X-OTX-API-KEY": otx_key} if otx_key else {}
    
    # বাংলাদেশ বা গ্লোবাল রিয়েল-টাইম অ্যাক্টিভ পালস বা থ্রেট ফিড
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
    if not otx_key:
        # ওটিএক্স কি না থাকলে পাবলিকলি অ্যাভেলেবল রিসেন্ট মডিফাইড ফিড ব্যবহার করবে
        url = "https://otx.alienvault.com/api/v1/pulses/explore?limit=10&sort=-modified"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json().get("results", [])
    except Exception as e:
        print(f"[-] Error fetching OTX data: {e}")
    return []

def extract_iocs(pulse):
    """আইওসি তালিকা থেকে আইপি, ম্যালওয়্যার হ্যাশ ইত্যাদি আলাদা করবে।"""
    ips, malwares, cves = [], [], []
    for indicator in pulse.get("indicators", []):
        ind_type = indicator.get("type")
        value = indicator.get("indicator")
        if ind_type in ["IPv4", "IPv6"]:
            ips.append(value)
        elif ind_type in ["FileHash-SHA256", "FileHash-MD5"]:
            malwares.append(value[:15] + "...") # বড় হ্যাশ ট্রিম করা হলো
        elif ind_type == "CVE":
            cves.append(value)
    return list(set(ips))[:5], list(set(malwares))[:5], list(set(cves))[:5]

def get_ip_location(ip, ipinfo_key):
    """IPInfo API ব্যবহার করে অ্যাটাকারের কান্ট্রি ও লোকেশন বের করবে।"""
    if not ip:
        return "Unknown Location", "Unknown Country"
    url = f"https://ipinfo.io/{ip}?token={ipinfo_key}" if ipinfo_key else f"https://ipinfo.io/{ip}/json"
    try:
        res = requests.get(url, timeout=5).json()
        return res.get("loc", "Unknown"), res.get("country", "Unknown")
    except:
        return "Unknown", "Unknown"

def main():
    otx_key = os.getenv("OTX_API_KEY")
    discord_webhook = os.getenv("DISCORD_WEBHOOK")
    ipinfo_key = os.getenv("IPINFO_KEY")

    if not discord_webhook:
        print("[-] Error: DISCORD_WEBHOOK is required.")
        sys.exit(1)

    print("[*] Gathering Live Real-World Threat Intelligence...")
    pulses = fetch_real_threat_data(otx_key)
    
    if not pulses:
        print("[-] No active pulses fetched. Exiting.")
        return

    # ইতিমধ্যে প্রসেস হওয়া পালস ট্র্যাক করার জন্য (ডুপ্লিকেট এড়াতে)
    processed_file = "docs/live_threats.json"
    existing_ids = []
    if os.path.exists(processed_file):
        try:
            with open(processed_file, "r") as f:
                old_data = json.load(f)
                existing_ids = [item["id"] for item in old_data if "id" in item]
        except:
            existing_ids = []

    new_threats_to_save = []

    for pulse in pulses:
        pulse_id = pulse.get("id")
        
        # ডুপ্লিকেট অ্যালার্ট ফিল্টারিং (যা আগে পাঠানো হয়নি)
        if pulse_id in existing_ids:
            continue

        # APT Group বা অ্যাটাকার ডিটেইলস এক্সট্রাক্ট করা (নন-উইকিপিডিয়া/আননোন হলে 'Unknown APT' দেখাবে)
        targeted_adversaries = pulse.get("adversaries", [])
        apt_group = targeted_adversaries[0] if targeted_adversaries else "Unknown APT Group / Cyber Campaign"
        
        # অ্যাটাকের টার্গেট বা ভিকটিম ইনফরমেশন
        targeted_industries = pulse.get("targeted_countries", []) or ["Global / Multiple Sectors"]
        victim = ", ".join(targeted_industries)

        # আইওসি, ম্যালওয়্যার এবং সিভিই এক্সট্রাকশন
        ips, malwares, cves = extract_iocs(pulse)
        
        # ফার্স্ট আইপি ডিটেক্ট করে লোকেশন বের করা
        primary_ip = ips[0] if ips else None
        location, country = get_ip_location(primary_ip, ipinfo_key)

        # ডিস্কোর্ড এম্বেড ডেটা ফরম্যাটিং
        embed = {
            "title": f"🚨 REAL ATTACK DETECTED: {pulse.get('name')}",
            "description": f"**Description:** {pulse.get('description', 'No description provided.')[:300]}...",
            "color": 16507648, # Orange/Red Alert Color
            "fields": [
                {"name": "👤 APT Group / Threat Actor", "value": str(apt_group), "inline": True},
                {"name": "🌍 Actor Country / Location", "value": f"{country} ({location})", "inline": True},
                {"name": "🎯 Victim / Target Country", "value": str(victim), "inline": True},
                {"name": "💻 Exploited CVE(s)", "value": ", ".join(cves) if cves else "None Identified", "inline": True},
                {"name": "🦠 Malware / IOC Hashes", "value": ", ".join(malwares) if malwares else "None Identified", "inline": False},
                {"name": "🌐 Attacking IP Address(es)", "value": ", ".join(ips) if ips else "None Identified", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": f"Pulse ID: {pulse_id} | Real-Time BD Cyber Command Intel"}
        }

        # ডিস্কোর্ডে লাইভ অ্যালার্ট পাঠানো
        send_discord_webhook(discord_webhook, embed)
        
        # ডাটাবেজ বা ফাইল আপডেটের জন্য সেভ রাখা
        new_threats_to_save.append({
            "id": pulse_id,
            "name": pulse.get("name"),
            "apt_group": apt_group,
            "ips": ips,
            "location": f"{country} ({location})",
            "malware": malwares,
            "cve": cves,
            "victim": victim,
            "date": datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        })

    # JSON ফাইল মেইনটেইন করা
    if new_threats_to_save:
        os.makedirs("docs", exist_ok=True)
        # পুরাতন ডেটার সাথে নতুন ডেটা যোগ করা
        try:
            with open(processed_file, "r") as f:
                current_db = json.load(f)
        except:
            current_db = []
            
        updated_db = new_threats_to_save + current_db
        with open(processed_file, "w") as f:
            json.dump(updated_db[:100], f, indent=4) # সর্বোচ্চ ১০০টি রেকর্ড হিস্ট্রি রাখবে কনফ্লিক্ট এড়াতে
        print(f"[+] Successfully saved {len(new_threats_to_save)} new threat records.")

if __name__ == "__main__":
    main()
