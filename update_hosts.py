import urllib.request
import re

# HaGeZi's NSFW/Porn light list (change URL if you prefer normal or multi)
URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt"
OUTPUT_FILE = "hosts_nsfw.txt"
TARGET_IP = "0.0.0.0"
DOMAINS_PER_LINE = 9

def generate_hosts():
    print(f"Fetching HaGeZi list...")
    try:
        req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
    except Exception as e:
        print(f"Error fetching list: {e}")
        return

    # Parse domains, ignoring comments, empty lines, and wildcard markers (*.)
    domains = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # HaGeZi lists use '||domain.com^' or '*.domain.com' or just 'domain.com'
        clean = line.replace("||", "").replace("^", "").replace("*.", "").strip()
        if clean:
            domains.append(clean)

    print(f"Found {len(domains)} domains. Chunking...")

    # Chunk into lines of 9
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# HaGeZi NSFW Windows Defense-in-Depth List\n")
        f.write(f"# Total original domains: {len(domains)}\n\n")
        
        for i in range(0, len(domains), DOMAINS_PER_LINE):
            chunk = domains[i:i + DOMAINS_PER_LINE]
            f.write(f"{TARGET_IP} {' '.join(chunk)}\n")

    print(f"Done! Saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_hosts()
