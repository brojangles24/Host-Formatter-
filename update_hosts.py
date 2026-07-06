import urllib.request
import socket

# 1. Core Blocklist Sources (Target: 0.0.0.0)
BLOCKLIST_URLS = [
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nosafesearch.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/social.txt",
]

# 2. Upstream AdGuard SafeSearch Source Feeds
SAFESEARCH_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt"
]

OUTPUT_FILE = "hosts.txt"
DOMAINS_PER_LINE = 9

def generate_hosts():
    # --- STEP 1: Process Standard Blocklists ---
    blocked_domains = set()
    for url in BLOCKLIST_URLS:
        print(f"Fetching blocklist: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8')
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    clean = line.replace("127.0.0.1", "").replace("0.0.0.0", "")
                    clean = clean.replace("||", "").replace("^", "").replace("*.", "").strip()
                    if clean:
                        blocked_domains.add(clean)
        except Exception as e:
            print(f"Error fetching blocklist: {e}")

    sorted_blocked = sorted(list(blocked_domains))

    # --- STEP 2: Parse Complex AdGuard SafeSearch Formats ---
    safesearch_mappings = {}
    resolved_hosts_cache = {}

    for url in SAFESEARCH_URLS:
        print(f"Fetching SafeSearch rules: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read().decode('utf-8')
                
                for line in content.splitlines():
                    line = line.strip()
                    if "$dnsrewrite=" in line:
                        try:
                            # Split string into domain segment and rewrite segment
                            left_side, right_side = line.split("$dnsrewrite=")
                            
                            # Clean the source domain (removes AdGuard's leading | and trailing ^)
                            clean_domain = left_side.replace("|", "").replace("^", "").strip()
                            if not clean_domain:
                                continue
                            
                            # Parse AdGuard instruction arguments (e.g., NOERROR;CNAME;strict.bing.com)
                            rewrite_parts = right_side.split(";")
                            if len(rewrite_parts) < 3:
                                continue
                                
                            record_type = rewrite_parts[1].upper() # CNAME or A
                            target_value = rewrite_parts[2].strip() # The destination host or IP
                            
                            ip = None
                            if record_type == "A":
                                # Target value is already a hardcoded IP address string
                                ip = target_value
                            elif record_type == "CNAME":
                                # Target value is a hostname, resolve it dynamically
                                if target_value in resolved_hosts_cache:
                                    ip = resolved_hosts_cache[target_value]
                                else:
                                    try:
                                        ip = socket.gethostbyname(target_value)
                                        resolved_hosts_cache[target_value] = ip
                                    except Exception:
                                        continue # Skip entry if lookup fails
                            
                            if ip:
                                if ip not in safesearch_mappings:
                                    safesearch_mappings[ip] = set()
                                safesearch_mappings[ip].add(clean_domain)
                                
                        except Exception:
                            continue # Skip malformed layout lines safely
        except Exception as e:
            print(f"Error fetching SafeSearch list: {e}")

    # --- STEP 3: Write Consolidated File Output ---
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# Consolidated Windows Defense-in-Depth List\n")
        f.write(f"# Total Blocked Domains: {len(sorted_blocked)}\n\n")
        
        # Write Blocklist Chunks (0.0.0.0 target mapping)
        for i in range(0, len(sorted_blocked), DOMAINS_PER_LINE):
            chunk = sorted_blocked[i:i + DOMAINS_PER_LINE]
            f.write(f"0.0.0.0 {' '.join(chunk)}\n")
            
        # Write SafeSearch Mapping Chunks organized by Virtual IP target destinations
        if safesearch_mappings:
            f.write("\n# ==========================================\n")
            f.write("# ENFORCED SAFESEARCH MAPPINGS (VIA ADGUARD)\n")
            f.write("# ==========================================\n\n")
            
            for ip, domains_set in safesearch_mappings.items():
                sorted_ss_domains = sorted(list(domains_set))
                f.write(f"# Target Destination VIP: {ip}\n")
                for i in range(0, len(sorted_ss_domains), DOMAINS_PER_LINE):
                    chunk = sorted_ss_domains[i:i + DOMAINS_PER_LINE]
                    f.write(f"{ip} {' '.join(chunk)}\n")

    print(f"Done! Successfully generated structured {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_hosts()
