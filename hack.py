import random
import time
import sys
from datetime import datetime
import shutil





green = "\033[92m"
cyan = "\033[96m"
red = "\033[91m"
reset = "\033[0m"

charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/\\"

phrases = [
    "Bypassing enterprise-grade firewall using modified ruleset injection combined with a time-based desynchronization attack. Exploit deployed across edge nodes to suppress alert propagation temporarily and avoid tripwires during deep scan sequence initiation.",
    
    "Initiating brute-force decryption of SHA-512 hashed tokens retrieved from memory dump. Leveraging GPU parallelism to accelerate keyspace traversal. Estimated time to crack: variable depending on salt entropy and key density patterns.",
    
    "Establishing encrypted socket connection with remote command-and-control server over port 443 using custom TLS handshake spoofing. Routing through five geo-obfuscated proxies to ensure plausible deniability and avoid endpoint blacklisting.",
    
    "Injecting polymorphic payload into host memory via DLL side-loading vulnerability. Payload concealed inside digitally signed installer. Execution will trigger privilege escalation and initiate data exfiltration under root context.",
    
    "Accessing root directory by hijacking active session with elevated privileges. Exploiting misconfigured sudoers file to suppress audit logs and establish persistence via cronjob injector in `/etc/cron.d`.",
    
    "Decrypting multi-layered authentication tokens retrieved from cloud config repo. Using pre-trained GPT-model to infer structure of custom auth scheme and simulate token response for lateral movement validation.",
    
    "Reverse shell successfully established using outbound DNS tunnel. Shell bound to ephemeral port, disguised as system telemetry. Awaiting command input from operator console. Persistence ensured via registry patch.",
    
    "Breaching secured VLAN segment by leveraging ARP spoofing attack and crafting fake DHCP offers. Temporary man-in-the-middle state achieved. Beginning protocol sniffing to harvest login sessions and token metadata.",
    
    "Spoofing MAC address of admin workstation on subnet 10.0.5.1 using forged ARP requests. Bypassing MAC filtering on router to gain access to restricted configuration interface.",
    
    "Overriding BIOS security settings by flashing updated firmware through vulnerable vendor utility. Exploit injects custom bootloader allowing future cold boot payloads to initialize before OS security is loaded.",
    
    "Launching distributed brute-force attack on admin login portal using slow-rate threading to avoid rate-limiting defenses. Credentials dictionary curated from known employee leaks and corporate naming conventions.",
    
    "Opening encrypted backdoor channel disguised as routine HTTPS traffic. Beacon interval randomized every 15 seconds. Payload triggers upon presence of custom base64 marker in header.",
    
    "Initiating download of confidential files from `/mnt/secure-share/internal/hr_docs`. Session disguised as nightly backup task. Transfer routed through onion relay using base64-wrapped zip container.",
    
    "Privilege escalation in progress. Using dirty pipe kernel vulnerability to write arbitrary data into system process memory. Targeted process: systemd with `cap_sys_admin` privileges.",
    
    "Enumerating all active subdomains using DNS brute-force and certificate transparency logs. Matching results against known open ports to shortlist exploitable application endpoints.",
    
    "Listening on port 1337 for reverse shell callbacks. All incoming payloads encrypted using XOR cipher. Matching fingerprints against known C2 implant signatures.",
    
    "IDS evasion in progress. Payloads are now encoded using custom base58 scheme. Traffic randomized to mimic regular SaaS activity. False negatives likely in heuristic engines.",
    
    "Deploying zero-day exploit targeting unpatched version of Apache HTTPD running on remote host. Shellcode obfuscated using alphanumeric encoding. Watchdog script deployed for retry loop.",
    
    "Flushing IP tables on compromised host to disable all firewall rules. System now openly accepting external connections on all ports. Persistence will be re-established via init script.",
    
    "Packet sniffing activated on internal subnet. Capturing all unencrypted traffic and extracting credentials, session tokens, and API keys. Filtering for known internal app patterns.",
    
    "Remote command execution triggered via deserialization flaw in Java-based microservice. Code injected through malformed cookie header. Execution confirmed with beacon ping to C2 node.",
    
    "Tunneling into internal network via compromised VPN gateway. Traffic encapsulated inside WebSocket streams. Authenticated as internal support user using stolen credentials.",
    
    "Compiling malicious binary from obfuscated Go source. Static binary will include embedded payload and RSA exfil key. Will deploy to `/usr/local/bin/update` on target.",
    
    "Extracting private RSA keys from memory snapshot. Using timing attack on decrypt function to infer bits of private exponent. Key entropy degradation detected—reconstruction likely within minutes.",
    
    "Bypassing two-factor authentication by hijacking valid session cookie before challenge prompt. Spoofed session injected into alternate browser profile with valid user context.",
    
    "Hijacking DNS requests by poisoning cache on internal DNS resolver. Redirecting internal services to fake mirrors for credential harvesting. TTL set to 1 hour to avoid detection.",
    
    "Injecting SQL command via vulnerable `search.php` parameter. Using time-based blind injection to enumerate column structure. Extracting hashed credentials from `users` table.",
    
    "Scanning for open ports across all discovered subnets. Using randomized timing and source IP spoofing to avoid scan detection. Prioritizing results with known vulnerable services.",
    
    "Access granted. Admin shell spawned on target system. UID confirmed as 0. Target identified as `mainframe-01.internal.corp`. Deploying persistence module and cleaning audit logs.",
    
    "Uploading RAT to target host using hidden SMB share. Binary disguised as log analyzer tool. Execution scheduled via hidden task in Task Scheduler.",
    
    "Intercepting session token from compromised endpoint using JavaScript payload injected into analytics script. Token replay successful on dashboard interface. Privilege level: admin.",
    
    "System logs disabled using direct tampering of journal binary. Log writing halted. Previous entries purged using overwrite and truncation methods. Audit trail now unrecoverable.",
    
    "Dumping full physical memory from remote system using `/dev/mem` interface. Writing to raw disk blob. Will analyze offline for credentials, keys, and socket handles.",
    
    "Triggering buffer overflow in C-based login service. Input crafted with NOP sled followed by shellcode. SEH overwritten. Shell will bind on port 8088 if successful.",
    
    "Kernel module tampering in progress. Malicious module inserted using insmod and LKM rootkit. Hiding all malicious processes, ports, and files from userland tools.",
    
    "Firmware dump complete. Flash contents of router saved to binary blob. Static credential table and session handling logic exposed. Firmware modification pending and will reflash post analysis.",
    
    "Decrypting AES-256 encrypted blob using known-plaintext pattern injection. Analyzing entropy drop for vulnerability. Estimated success probability: 78% within current compute capacity.",
    
    "Injecting JavaScript payload into live website footer via exposed CMS admin panel. Payload includes keylogger and token harvester. Callback triggered every 30 seconds.",
    
    "Man-in-the-middle attack deployed. Intercepting HTTPS connections by spoofing root certificate on target machine. Traffic decryption successful using custom proxy binary.",
    
    "Parsing leaked password dump file. Using Levenshtein distance to group likely user variations. Matching hash outputs with internal employee accounts.",
    
    "Connecting to darknet node on port 9050 via Tor proxy. Fetching marketplace API keys and uploading stolen documents under random alias. Transaction anonymized.",
    
    "Remote session hijack complete. Impersonating user session on internal dashboard. Access level: admin+. No MFA detected. Exfil tools deployed.",
    
    "Fingerprinting host operating system by analyzing TCP/IP stack behavior and ICMP TTL response timing. OS guessed: Ubuntu 22.04 with hardened kernel.",
    
    "Passive reconnaissance in progress. Harvesting LinkedIn, GitHub, and StackOverflow profiles for target employees. Compiling social graph for spearphishing entry vector.",
    
    "Tracking GPS metadata from recently uploaded images to internal asset portal. Geotags suggest sensitive facility location. Elevation data implies high-security floor.",
    
    "Tampering with blockchain ledger by injecting false transaction batch with forged signature. Smart contract logic exploited due to missing timestamp check.",
    
    "Building chained exploit using CVE-2023-26853 followed by token abuse chain. All dependencies injected via base64 blob in HTTP header.",
    
    "Launching coordinated DDoS attack using 4700 botnet nodes. Traffic split across multiple layers. Attack disguised as legitimate cloud storage queries.",
    
    "Bypassing lockdown policy using live kernel patch. Injecting new syscall to grant root shell regardless of auth state. Patch will auto-revert after 5 minutes.",
    
    "Root shell confirmed. Privileges escalated to full system access. All watchdogs disabled. You are now inside. Begin cleanup and deploy exit beacon.",
    
    "Accessing deep archive of classified files. Archive mounted under hidden volume. Contents include blueprints, NDAs, surveillance logs. Download underway. Do not interrupt."
]


headings = [
    "Initializing Exploit Chain",
    "Getting Core Access",
    "Activating Persistence Module",
    "Launching Recon Protocol",
    "Extracting Secrets from Memory Dump",
    "Establishing Command and Control",
    "Compiling RAT Payload",
    "Deploying Rootkit",
    "Escalating Privileges to Root",
    "Injecting Code into Protected Process",
    "Cloning Access Tokens",
    "Harvesting API Keys",
    "Flushing Firewall Rules",
    "Bypassing Multi-Factor Authentication",
    "Sniffing Unencrypted Credentials",
    "Reverse Shell Online",
    "Downloading Confidential Archives",
    "Hijacking Active Session",
    "Injecting Backdoor into Bootloader",
    "Cracking Encrypted Vault",
]

def get_terminal_width(default=120):
    return max(shutil.get_terminal_size(fallback=(default, 20)).columns, 80)

def random_line():
    width = get_terminal_width()
    return ''.join(random.choice(charset) for _ in range(width))



def print_heading(text):
    width = get_terminal_width()
    text = f" {text} "
    padding = width - len(text)

    if padding < 0:
        text = text[:width - 4] + "..."  # truncate long heading
        padding = width - len(text)

    left = padding // 2
    right = padding - left

    topline = "#" * width
    banner = "#" * left + text + "#" * right

    print(cyan + topline + reset)
    print(cyan + banner + reset)
    print(cyan + topline + reset + "\n")




def type_phrase(phrase, status="OK", tag="INFO"):
    now = datetime.now().strftime("%H:%M:%S")
    status_map = {
        "OK": green + "[OK]" + reset,
        "FAIL": red + "[FAIL]" + reset,
        "IN PROGRESS": cyan + "[...]" + reset,
        "WARN": "\033[93m[WARN]\033[0m"
    }

    tag_colored = {
        "RECON": cyan + "[RECON]" + reset,
        "EXPLOIT": red + "[EXPLOIT]" + reset,
        "EXFIL": green + "[EXFIL]" + reset,
        "PERSIST": "\033[95m[PERSIST]\033[0m",
        "INFO": "\033[94m[INFO]" + reset,
        "ACCESS": "\033[96m[ACCESS]" + reset
    }.get(tag.upper(), cyan + "[LOG]" + reset)

    header = f"{cyan}[{now}]{reset} {tag_colored} {status_map.get(status, status)}"
    
    print(header)
    speed = random.uniform(0.003, 0.01)
    for char in phrase:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print("\n")

def show_loader(text="Processing request", duration=random.uniform(1.5, 6.0)):
    bar_len = get_terminal_width() - len(text) - 15
    bar_len = max(min(bar_len, 200), 30)  # Clamp bar length

    for i in range(bar_len + 1):
        percent = int((i / bar_len) * 100)
        bar = "=" * i + " " * (bar_len - i)
        sys.stdout.write("\r" + " " * (bar_len + 50) + "\r")  # Clear line
        sys.stdout.write(f"{cyan}{text}:{reset} [{green}{bar}{reset}] {percent:3d}%")
        sys.stdout.flush()
        time.sleep(duration / bar_len)

    sys.stdout.write("\r" + " " * (bar_len + 50) + "\r")
    sys.stdout.write(f"{cyan}{text}:{reset} [{green}{'=' * bar_len}{reset}] {green}Done.{reset}\n")
    sys.stdout.flush()




def run_terminal_animation_by_name(name):
    width = get_terminal_width()

    if name == "data_block":
        for _ in range(10):
            line = ''.join(random.choice(charset) for _ in range(width))
            print(green + line + reset)
            time.sleep(random.uniform(0.04, 0.08))

    elif name == "matrix_scan":
        for _ in range(12):
            line = ''
            for _ in range(width):
                char = random.choice(charset)
                color = green if random.random() > 0.05 else cyan
                line += color + char + reset
            print(line)
            time.sleep(random.uniform(0.03, 0.06))

    elif name == "center_wave":
    # Steady stream of flowing horizontal wave patterns
        wave_chars = "~^*=+#"
        for _ in range(10):
            wave = ''.join(random.choice(wave_chars) for _ in range(width))
            print(green + wave + reset)
            time.sleep(random.uniform(0.04, 0.08))

    elif name == "cyber_grid":
        for _ in range(8):
            row = []
            for _ in range(12):  # 4 characters per cell
                cell = ''.join(random.choice("0123456789ABCDEF") for _ in range(4))
                row.append(cell)
            print(cyan + "  ".join(row) + reset)
            time.sleep(0.08)





def main():
    print(green + "[*] Initiating Hack Sequence...\n" + reset)

    last_phrase_time = time.time()
    phrase_interval = random.uniform(6, 14)

    # Define animation rotation
    anim_pool = ["data_block", "matrix_scan", "center_wave", "cyber_grid"]
    animation_index = 0
    last_action = "phrase"  # start with phrase or loader

    try:
        while True:
            now = time.time()

            if last_action == "animation":
                # Run a phrase or loader now
                if random.random() < 0.25:
                    show_loader("Processing request", duration=random.uniform(2.5, 4.0))
                else:
                    phrase = random.choice(phrases)
                    tag = random.choice(["RECON", "EXPLOIT", "EXFIL", "PERSIST", "ACCESS"])
                    status = random.choice(["OK", "IN PROGRESS", "OK", "OK", "FAIL"])  # More OKs, fewer FAILs
                    type_phrase(phrase, status=status, tag=tag)
                    print("\n")
                last_action = "phrase"
            else:
                # Run next animation in sequence
                anim = anim_pool[animation_index]
                animation_index = (animation_index + 1) % len(anim_pool)
                run_terminal_animation_by_name(anim)
                last_action = "animation"

            # Occasionally show a standalone phrase
            if now - last_phrase_time > phrase_interval:
                phrase = random.choice(phrases)
                tag = random.choice(["RECON", "EXPLOIT", "EXFIL", "PERSIST", "ACCESS"])
                status = random.choice(["OK", "IN PROGRESS", "OK", "OK", "FAIL"])  # More OKs, fewer FAILs
                type_phrase(phrase, status=status, tag=tag)
                last_phrase_time = now
                phrase_interval = random.uniform(6, 14)

            if random.random() < 0.3:  # 30% chance to print a heading
                print_heading(random.choice(headings))

    except KeyboardInterrupt:
        print(red + "\n[!] Hack Session Terminated" + reset)



if __name__ == "__main__":
    main()
