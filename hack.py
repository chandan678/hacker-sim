import random
import time
import sys
from datetime import datetime
import shutil
import platform
import socket
import os
import subprocess
import uuid
import hashlib


# ──── Terminal Colors & Styles ────
green = "\033[92m"
cyan = "\033[96m"
red = "\033[91m"
yellow = "\033[93m"
magenta = "\033[95m"
blue = "\033[94m"
white = "\033[97m"
bold = "\033[1m"
dim = "\033[2m"
blink = "\033[5m"
reset = "\033[0m"
bg_red = "\033[41m"
bg_green = "\033[42m"

charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/\\"


# ──── Real System Info (safe, read-only) ────

def get_real_sysinfo():
    """Gather real but safe system information for realistic output."""
    info = {}
    info['hostname'] = socket.gethostname()
    info['username'] = os.getenv('USER', os.getenv('USERNAME', 'operator'))
    info['os'] = platform.system()
    info['os_version'] = platform.version()
    info['os_release'] = platform.release()
    info['arch'] = platform.machine()
    info['processor'] = platform.processor()
    info['python'] = platform.python_version()
    info['node'] = platform.node()
    info['cpu_count'] = os.cpu_count() or 4

    # Local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info['local_ip'] = s.getsockname()[0]
        s.close()
    except Exception:
        info['local_ip'] = '192.168.1.' + str(random.randint(2, 254))

    # Network interfaces
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=3)
        interfaces = []
        for line in result.stdout.split('\n'):
            if line and not line.startswith('\t') and not line.startswith(' '):
                iface = line.split(':')[0]
                if iface:
                    interfaces.append(iface)
        info['interfaces'] = interfaces[:8]
    except Exception:
        info['interfaces'] = ['en0', 'lo0', 'utun0', 'awdl0']

    # MAC address
    mac = uuid.getnode()
    info['mac'] = ':'.join(f'{(mac >> i) & 0xFF:02x}' for i in range(40, -1, -8))

    # Uptime
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=3)
        info['uptime'] = result.stdout.strip()
    except Exception:
        info['uptime'] = 'up 14 days, 3:27'

    # Disk
    try:
        result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=3)
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            info['disk'] = lines[1]
    except Exception:
        info['disk'] = '/dev/disk1s1  466Gi  234Gi  220Gi  52%  /System/Volumes/Data'

    return info


def get_running_processes():
    """Get real process names for realistic display."""
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=3)
        lines = result.stdout.strip().split('\n')[1:]
        processes = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 11:
                processes.append({
                    'user': parts[0],
                    'pid': parts[1],
                    'cpu': parts[2],
                    'mem': parts[3],
                    'command': ' '.join(parts[10:])[:60]
                })
        random.shuffle(processes)
        return processes[:30]
    except Exception:
        return []


def generate_fake_ips(count=20):
    """Generate realistic IPs using real local subnet."""
    sysinfo = get_real_sysinfo()
    local = sysinfo['local_ip']
    base = '.'.join(local.split('.')[:3])
    ips = []
    for _ in range(count):
        if random.random() < 0.6:
            ips.append(f"{base}.{random.randint(1, 254)}")
        else:
            ips.append(f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
    return ips


def generate_session_id():
    return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16].upper()


def generate_fake_hash():
    return hashlib.sha512(str(random.random()).encode()).hexdigest()


# ──── Cache sysinfo at module load so it's fast during animation ────
_SYSINFO = None

def sysinfo():
    global _SYSINFO
    if _SYSINFO is None:
        _SYSINFO = get_real_sysinfo()
    return _SYSINFO


# ──── Phrases ────

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


# ════════════════════════════════════════════════════════
#  CORE DISPLAY FUNCTIONS
# ════════════════════════════════════════════════════════

def get_terminal_width(default=120):
    return max(shutil.get_terminal_size(fallback=(default, 20)).columns, 80)


def print_heading(text):
    width = get_terminal_width()
    text = f" {text} "
    padding = width - len(text)

    if padding < 0:
        text = text[:width - 4] + "..."
        padding = width - len(text)

    left = padding // 2
    right = padding - left

    topline = "█" * width
    banner = "█" * left + text.upper() + "█" * right
    botline = "█" * width

    print()
    print(cyan + bold + topline + reset)
    print(cyan + bold + banner + reset)
    print(cyan + bold + botline + reset)
    print()


def type_phrase(phrase, status="OK", tag="INFO"):
    now = datetime.now().strftime("%H:%M:%S.") + f"{random.randint(100,999)}"
    status_map = {
        "OK": green + bold + "[  OK  ]" + reset,
        "FAIL": red + bold + "[ FAIL ]" + reset,
        "IN PROGRESS": cyan + "[  ··  ]" + reset,
        "WARN": yellow + "[ WARN ]" + reset,
    }

    tag_colored = {
        "RECON": cyan + bold + "[RECON]" + reset,
        "EXPLOIT": red + bold + "[EXPLOIT]" + reset,
        "EXFIL": green + bold + "[EXFIL]" + reset,
        "PERSIST": magenta + bold + "[PERSIST]" + reset,
        "INFO": blue + "[INFO]" + reset,
        "ACCESS": yellow + bold + "[ACCESS]" + reset,
        "C2": red + "[C2]" + reset,
        "CRYPTO": magenta + "[CRYPTO]" + reset,
    }.get(tag.upper(), cyan + "[LOG]" + reset)

    header = f"  {dim}{now}{reset}  {tag_colored}  {status_map.get(status, status)}"

    print(header)
    speed = random.uniform(0.004, 0.012)
    sys.stdout.write("  ")
    for char in phrase:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print("\n")


def show_loader(text="Processing request", duration=None):
    if duration is None:
        duration = random.uniform(1.5, 5.0)
    bar_len = get_terminal_width() - len(text) - 20
    bar_len = max(min(bar_len, 200), 30)

    blocks = ['░', '▒', '▓', '█']

    for i in range(bar_len + 1):
        percent = int((i / bar_len) * 100)
        filled = '█' * i
        trail = '▓' if i < bar_len else ''
        empty = '░' * max(0, bar_len - i - 1)
        bar = filled + trail + empty

        sys.stdout.write("\r" + " " * (bar_len + 60) + "\r")
        sys.stdout.write(f"  {cyan}{text}:{reset} [{green}{bar}{reset}] {white}{bold}{percent:3d}%{reset}")
        sys.stdout.flush()
        time.sleep(duration / bar_len)

    sys.stdout.write("\r" + " " * (bar_len + 60) + "\r")
    sys.stdout.write(f"  {cyan}{text}:{reset} [{green}{'█' * bar_len}{reset}] {green}{bold}Done.{reset}\n")
    sys.stdout.flush()


# ════════════════════════════════════════════════════════
#  LIGHT ANIMATIONS (fast data streams)
# ════════════════════════════════════════════════════════

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
                color = green if random.random() > 0.08 else cyan
                line += color + char + reset
            print(line)
            time.sleep(random.uniform(0.03, 0.06))

    elif name == "center_wave":
        wave_chars = "~^*=+#░▒▓█"
        for _ in range(10):
            wave = ''.join(random.choice(wave_chars) for _ in range(width))
            print(green + wave + reset)
            time.sleep(random.uniform(0.04, 0.08))

    elif name == "cyber_grid":
        for _ in range(8):
            row = []
            for _ in range(12):
                cell = ''.join(random.choice("0123456789ABCDEF") for _ in range(4))
                row.append(cell)
            print(cyan + "  ".join(row) + reset)
            time.sleep(0.08)

    elif name == "binary_rain":
        for _ in range(8):
            line = ''
            for _ in range(width):
                if random.random() < 0.15:
                    line += green + bold + random.choice('01') + reset
                else:
                    line += dim + random.choice('01') + reset
            print(line)
            time.sleep(random.uniform(0.02, 0.05))
        print()


# ════════════════════════════════════════════════════════
#  HEAVY VISUALS (realistic hacking displays)
# ════════════════════════════════════════════════════════

def hex_dump_animation():
    """Wireshark-style hex + ASCII dump of intercepted data."""
    contexts = [
        ("HTTP response header", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: Express\r\nSet-Cookie: session=eyJhbGciOi; HttpOnly; Secure\r\nContent-Type: application/json\r\n\r\n{\"status\":\"authenticated\",\"role\":\"admin\",\"token\":\"sk-"),
        ("SSH handshake", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n\x00\x00\x03\x14\x08\x14curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256"),
        ("RSA private key fragment", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi..ZYtQ9Lqx\nA7JsyzVB0iA5kOT+Rhn6X2I2PnLEtbiXq0YN7+SM=\n-----END RSA PRI"),
        ("Database credential dump", "root:$6$rounds=656000$Q8kCm4nJ$KJhwA4rl3yz...:19287:0:99999:7:::\ndaemon:*:19287:0:99999:7:::\ndb_admin:$6$xR5kTm$Yx4MnsK"),
        ("JWT token payload", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InN1cGVyX2FkbWluIiwiaWF0IjoxNjk"),
        ("Kerberos ticket", "\x00\x00\x00\x02krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL\x00\x00\x00\x01\x00\x00\x00\x12\x00\x00\x00 "),
    ]

    label, raw = random.choice(contexts)
    while len(raw) < 160:
        raw += chr(random.randint(32, 126))

    print(f"\n  {cyan}{'─' * 72}{reset}")
    print(f"  {yellow}{bold}◆ Intercepted {label} — {len(raw)} bytes captured{reset}")
    print(f"  {cyan}{'─' * 72}{reset}")
    print(f"  {dim}  Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   Decoded{reset}")
    print(f"  {cyan}{'─' * 72}{reset}")

    offset = random.randint(0, 0xFFFF) & 0xFFF0
    for i in range(0, min(len(raw), 160), 16):
        chunk = raw[i:i + 16]
        hex1 = ' '.join(f'{ord(c):02X}' for c in chunk[:8])
        hex2 = ' '.join(f'{ord(c):02X}' for c in chunk[8:16])
        asc = ''.join(c if 32 <= ord(c) < 127 else '.' for c in chunk)

        hex1 = hex1.ljust(23)
        hex2 = hex2.ljust(23)

        print(f"  {green}{offset + i:08X}{reset}  {hex1}  {hex2}   {cyan}|{asc}|{reset}")
        time.sleep(random.uniform(0.04, 0.09))

    print(f"  {cyan}{'─' * 72}{reset}\n")
    time.sleep(0.3)


def port_scan_animation():
    """Nmap-style port scan with realistic output."""
    target_ip = generate_fake_ips(1)[0]

    services = [
        ("22/tcp", "open", "ssh", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1"),
        ("80/tcp", "open", "http", "nginx/1.18.0 (Ubuntu)"),
        ("443/tcp", "open", "ssl/https", "Apache/2.4.54 (Debian)"),
        ("3306/tcp", "filtered", "mysql", ""),
        ("5432/tcp", "open", "postgresql", "PostgreSQL 14.5"),
        ("6379/tcp", "open", "redis", "Redis 7.0.5"),
        ("8080/tcp", "open", "http-proxy", "Squid/4.13"),
        ("8443/tcp", "filtered", "https-alt", ""),
        ("27017/tcp", "open", "mongodb", "MongoDB 6.0.2"),
        ("9200/tcp", "open", "elasticsearch", "Elastic 8.5.0"),
        ("2222/tcp", "open", "ssh", "OpenSSH 9.1"),
        ("1433/tcp", "filtered", "ms-sql-s", ""),
        ("5900/tcp", "closed", "vnc", ""),
        ("8888/tcp", "open", "http", "Jupyter Notebook 6.5.2"),
        ("9090/tcp", "open", "http", "Prometheus/2.40"),
        ("11211/tcp", "open", "memcache", "Memcached 1.6.17"),
        ("4444/tcp", "open", "krb524", ""),
        ("1337/tcp", "open", "waste", ""),
    ]

    chosen = random.sample(services, random.randint(6, 12))
    chosen.sort(key=lambda x: int(x[0].split('/')[0]))

    print(f"\n  {white}{bold}Starting Nmap 7.94 ( https://nmap.org ) at {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC{reset}")
    time.sleep(0.4)
    print(f"  {dim}Nmap scan report for {target_ip}{reset}")
    print(f"  {dim}Host is up ({random.uniform(0.001, 0.05):.4f}s latency).{reset}")
    print(f"  {dim}Not shown: {random.randint(980, 995)} closed tcp ports (conn-refused){reset}\n")
    time.sleep(0.4)

    print(f"  {white}{bold}{'PORT':<14} {'STATE':<11} {'SERVICE':<18} {'VERSION'}{reset}")

    for port, state, service, version in chosen:
        state_color = green if state == "open" else (yellow if state == "filtered" else red)
        line = f"  {cyan}{port:<14}{reset} {state_color}{state:<11}{reset} {service:<18} {dim}{version}{reset}"
        print(line)
        time.sleep(random.uniform(0.12, 0.35))

    print(f"\n  {dim}Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .{reset}")
    print(f"  {dim}Nmap done: 1 IP address (1 host up) scanned in {random.uniform(8, 32):.2f} seconds{reset}\n")
    time.sleep(0.3)


def packet_capture_animation():
    """tcpdump-style live packet capture."""
    si = sysinfo()
    local_ip = si['local_ip']
    fake_ips = generate_fake_ips(10)
    flags = ['[S]', '[S.]', '[.]', '[P.]', '[F.]', '[R.]', '[P.]']

    iface = random.choice(si.get('interfaces', ['en0']))
    print(f"\n  {yellow}tcpdump: listening on {iface}, link-type EN10MB (Ethernet), snapshot length 262144 bytes{reset}")
    time.sleep(0.3)

    for _ in range(random.randint(15, 30)):
        ts = datetime.now().strftime("%H:%M:%S")
        ms = f".{random.randint(100000, 999999)}"
        src = random.choice([local_ip] + fake_ips)
        dst = random.choice(fake_ips + [local_ip])
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([22, 80, 443, 3306, 8080, 8443, 53, 5432, 6379, 27017])
        flag = random.choice(flags)
        seq = random.randint(1000000, 9999999)
        length = random.randint(0, 1460)

        print(f"  {dim}{ts}{ms}{reset} IP {green}{src}.{src_port}{reset} > {red}{dst}.{dst_port}{reset}: Flags {yellow}{flag}{reset}, seq {seq}:{seq + length}, ack {random.randint(1,9999999)}, win {random.choice([65535, 32768, 16384])}, length {length}")
        time.sleep(random.uniform(0.03, 0.12))

    pkt_count = random.randint(500, 5000)
    print(f"\n  {yellow}{pkt_count} packets captured{reset}")
    print(f"  {yellow}{pkt_count + random.randint(10, 100)} packets received by filter{reset}")
    print(f"  {yellow}{random.randint(0, 5)} packets dropped by kernel{reset}\n")
    time.sleep(0.3)


def memory_dump_animation():
    """Process memory dump with suspicious pattern detection."""
    pid = random.randint(1000, 65535)
    print(f"\n  {yellow}{bold}◆ Dumping process memory — PID {pid} ({random.choice(['sshd', 'nginx', 'java', 'node', 'python3', 'postgres'])}){reset}")
    print(f"  {cyan}{'─' * 62}{reset}")

    base_addr = random.choice([0x7FFE8A3C0000, 0x00400000, 0x7F4A2B100000, 0x55A3CC000000])

    interesting = [
        bytes([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]),  # PE header
        bytes([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]),  # ELF header
        bytes([0x50, 0x41, 0x53, 0x53, 0x57, 0x4F, 0x52, 0x44]),  # "PASSWORD"
        bytes([0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x5F, 0x4B]),  # "SECRET_K"
        bytes([0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E]),  # "---BEGIN"
        bytes([0x41, 0x57, 0x53, 0x5F, 0x4B, 0x45, 0x59, 0x3D]),  # "AWS_KEY="
    ]

    flagged_rows = sorted(random.sample(range(16), min(3, 16)))

    for i in range(16):
        addr = base_addr + (i * 8)
        if i in flagged_rows:
            data = random.choice(interesting)
        else:
            data = bytes(random.randint(0, 255) for _ in range(8))

        hex_str = ' '.join(f'{b:02X}' for b in data)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)

        highlight = red + bold if i in flagged_rows else green
        marker = f" {red}◄ FLAGGED{reset}" if i in flagged_rows else ""
        print(f"  {highlight}0x{addr:016X}{reset}  {hex_str}  {cyan}{asc}{reset}{marker}")
        time.sleep(random.uniform(0.04, 0.1))

    print(f"  {cyan}{'─' * 62}{reset}")
    print(f"  {red}{bold}⚠ {len(flagged_rows)} suspicious patterns found in memory region{reset}\n")
    time.sleep(0.4)


def file_tree_animation():
    """Filesystem traversal with status indicators."""
    si = sysinfo()
    hostname = si['hostname'].split('.')[0]
    username = si['username']

    targets = [
        (f"/home/{username}/.ssh/id_rsa", "FOUND", "extracting RSA private key..."),
        (f"/home/{username}/.ssh/authorized_keys", "FOUND", "3 public keys captured"),
        ("/etc/shadow", "LOCKED", "bypassing... DECRYPTED"),
        ("/etc/passwd", "READABLE", "48 user accounts enumerated"),
        ("/var/log/auth.log", "READING", f"{random.uniform(1.2, 8.7):.1f} MB captured"),
        ("/root/.bash_history", "FOUND", f"{random.randint(200, 2000)} commands recovered"),
        ("/etc/ssl/private/server.key", "LOCKED", "bruteforce in progress..."),
        (f"/home/{username}/.gnupg/secring.gpg", "FOUND", "GPG private key extracted"),
        ("/var/lib/mysql/users.ibd", "READING", "credential table located"),
        ("/opt/app/config/database.yml", "FOUND", "DB credentials in plaintext!"),
        ("/tmp/.hidden_backdoor", "WRITABLE", "payload deployed successfully"),
        (f"/home/{username}/.aws/credentials", "FOUND", "AWS access keys captured"),
        (f"/home/{username}/.kube/config", "FOUND", "K8s cluster token extracted"),
        ("/etc/kubernetes/pki/ca.key", "LOCKED", "CA key... attempting bypass"),
        ("/proc/self/environ", "READABLE", "environment variables dumped"),
        (f"/home/{username}/.docker/config.json", "FOUND", "Docker registry creds extracted"),
        ("/var/run/secrets/kubernetes.io/token", "FOUND", "service account token captured"),
        ("/opt/vault/data/core/keyring", "LOCKED", "Vault master key detected..."),
    ]

    chosen = random.sample(targets, random.randint(7, 12))

    print(f"\n  {yellow}{bold}◆ Traversing filesystem on {hostname}{reset}")
    print(f"  {cyan}{'─' * 72}{reset}")

    for path, status, detail in chosen:
        status_color = {
            "FOUND": green + bold,
            "LOCKED": red + bold,
            "READABLE": cyan,
            "READING": yellow,
            "WRITABLE": magenta + bold,
        }.get(status, white)

        dots = '·' * max(1, 58 - len(path))

        sys.stdout.write(f"  {dim}{path}{reset} ")
        sys.stdout.flush()
        time.sleep(random.uniform(0.1, 0.3))

        sys.stdout.write(f"{dim}{dots}{reset} ")
        sys.stdout.flush()
        time.sleep(random.uniform(0.05, 0.15))

        print(f"[{status_color}{status}{reset}] → {detail}")
        time.sleep(random.uniform(0.15, 0.4))

    print(f"  {cyan}{'─' * 72}{reset}\n")
    time.sleep(0.3)


def password_crack_animation():
    """Dramatic password cracking — characters lock in one by one."""
    target_user = random.choice(["admin", "root", "sysadmin", "db_admin", "operator", "backup_svc", "deploy_bot"])
    target_hash = generate_fake_hash()[:32]
    pw_len = random.randint(10, 16)
    final_pw = ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*") for _ in range(pw_len))

    print(f"\n  {red}{bold}◆ CRACKING PASSWORD HASH{reset}")
    print(f"  {dim}User:   {target_user}{reset}")
    print(f"  {dim}Hash:   {target_hash}...{reset}")
    print(f"  {dim}Method: Hybrid dictionary + mask attack (GPU accelerated){reset}\n")
    time.sleep(0.5)

    locked = [False] * pw_len

    for locked_count in range(pw_len):
        iterations = random.randint(10, 30)
        for _ in range(iterations):
            display = ''
            for j in range(pw_len):
                if locked[j]:
                    display += green + bold + final_pw[j] + reset
                else:
                    display += dim + random.choice(charset[:62]) + reset

            speed = random.randint(10000, 999999)
            bar_filled = int((locked_count / pw_len) * 20)
            bar = green + '█' * bar_filled + dim + '░' * (20 - bar_filled) + reset

            sys.stdout.write(f"\r  Password: [{display}]  {bar}  {speed:>9,} H/s  {yellow}{locked_count}/{pw_len}{reset}")
            sys.stdout.flush()
            time.sleep(random.uniform(0.02, 0.05))

        # Lock in next character
        pos = random.choice([i for i in range(pw_len) if not locked[i]])
        locked[pos] = True
        time.sleep(random.uniform(0.05, 0.2))

    # Final display
    cracked = green + bold + final_pw + reset
    print(f"\r  Password: [{cracked}]  {'█' * 20}  {green}{bold}CRACKED!{reset}{' ' * 30}")
    print(f"\n  {green}{bold}✓ Password recovered: {final_pw}{reset}")
    print(f"  {dim}  Time elapsed: {random.uniform(0.5, 45.0):.1f}s | Keyspace: {random.randint(1,9)}.{random.randint(0,9)}×10⁹{reset}\n")
    time.sleep(0.5)


def process_list_animation():
    """Show real processes with fake compromise status."""
    processes = get_running_processes()
    if not processes:
        return

    statuses = ["HOOKED", "INJECTED", "MONITOR", "CLEAN", "PATCHED", "ROOTKIT", "CLONED", "BACKDOOR"]
    status_colors = {
        "HOOKED": red,
        "INJECTED": red + bold,
        "MONITOR": yellow,
        "CLEAN": dim,
        "PATCHED": magenta,
        "ROOTKIT": red + bold,
        "CLONED": cyan,
        "BACKDOOR": red + bold,
    }

    print(f"\n  {yellow}{bold}◆ Process Injection Status{reset}")
    print(f"  {cyan}{'─' * 78}{reset}")
    print(f"  {bold}{'PID':<8} {'USER':<12} {'CPU%':<7} {'MEM%':<7} {'STATUS':<12} {'COMMAND'}{reset}")
    print(f"  {cyan}{'─' * 78}{reset}")

    shown = random.sample(processes, min(14, len(processes)))
    compromised = 0
    for p in shown:
        status = random.choices(statuses, weights=[3, 3, 2, 4, 1, 1, 1, 2])[0]
        if status not in ("CLEAN", "MONITOR"):
            compromised += 1
        scolor = status_colors.get(status, white)
        cmd = p['command'][:45]
        print(f"  {green}{p['pid']:<8}{reset} {dim}{p['user']:<12}{reset} {p['cpu']:<7} {p['mem']:<7} {scolor}[{status}]{reset}{'':>{10 - len(status)}} {dim}{cmd}{reset}")
        time.sleep(random.uniform(0.05, 0.15))

    print(f"  {cyan}{'─' * 78}{reset}")
    print(f"  {red}⚠ {compromised} processes compromised | {len(shown)} total scanned{reset}\n")
    time.sleep(0.3)


def sysinfo_fingerprint():
    """Display real system info in a dramatic bordered box."""
    si = sysinfo()
    session_id = generate_session_id()

    lines = [
        ("Hostname", si['hostname']),
        ("OS", f"{si['os']} {si['os_release']} ({si['arch']})"),
        ("Kernel", si['os_version'][:55]),
        ("Processor", si['processor'][:50] or f"{si['arch']} ({si['cpu_count']} cores)"),
        ("CPU Cores", str(si['cpu_count'])),
        ("Local IP", si['local_ip']),
        ("MAC Addr", si['mac']),
        ("Interfaces", ', '.join(si.get('interfaces', [])[:5])),
        ("Session", session_id),
    ]

    max_label = max(len(l) for l, _ in lines)
    max_val = max(len(v) for _, v in lines)
    box_w = max(max_label + max_val + 7, 55)

    print(f"\n  {cyan}┌{'─' * box_w}┐{reset}")
    print(f"  {cyan}│{reset}{red}{bold}{'TARGET SYSTEM FINGERPRINT':^{box_w}}{reset}{cyan}│{reset}")
    print(f"  {cyan}├{'─' * box_w}┤{reset}")

    for label, value in lines:
        content = f"  {yellow}{label:<{max_label}}{reset}  {green}{value}"
        padding = box_w - max_label - len(value) - 5
        print(f"  {cyan}│{reset}{content}{' ' * max(0, padding)} {cyan}│{reset}")
        time.sleep(random.uniform(0.08, 0.2))

    print(f"  {cyan}└{'─' * box_w}┘{reset}\n")
    time.sleep(0.4)


def fake_command_prompt():
    """Simulate typing a command at a root prompt, then show output."""
    si = sysinfo()
    hostname = si['hostname'].split('.')[0].lower()[:15]

    commands = [
        (f"cat /etc/shadow | head -5", [
            "root:$6$rounds=656000$rNds8x$KJh4Gm/w3pYxS...:19287:0:99999:7:::",
            "daemon:*:19287:0:99999:7:::",
            "bin:*:19287:0:99999:7:::",
            f"{si['username']}:$6$qR5k89$Yx4Mns...:19442:0:99999:7:::",
            "sshd:*:19287:0:99999:7:::",
        ]),
        ("netstat -tlnp 2>/dev/null | head -8", [
            "Active Internet connections (only servers)",
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program",
            f"tcp        0      0 {si['local_ip']}:22     0.0.0.0:*               LISTEN      {random.randint(500,2000)}/sshd",
            f"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      {random.randint(2000,5000)}/nginx",
            f"tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      {random.randint(2000,5000)}/nginx",
            f"tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      {random.randint(5000,9000)}/mysqld",
            f"tcp6       0      0 :::8080                 :::*                    LISTEN      {random.randint(9000,15000)}/java",
        ]),
        ("find / -name '*.pem' -o -name '*.key' 2>/dev/null | head -6", [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/private/server.key",
            f"/home/{si['username']}/.ssh/id_rsa",
            "/opt/app/certs/api-gateway.pem",
            "/var/lib/kubernetes/pki/apiserver.key",
            "/root/.docker/ca.pem",
        ]),
        ("whoami && id && uname -a", [
            "root",
            f"uid=0(root) gid=0(root) groups=0(root),27(sudo),998(docker)",
            f"{si['os']} {hostname} {si['os_release']} {si.get('os_version', '')[:45]} {si['arch']}"
        ]),
        (f"awk -F: '($3 == 0) {{print}}' /etc/passwd", [
            "root:x:0:0:root:/root:/bin/bash",
            f"{si['username']}:x:0:0::/home/{si['username']}:/bin/bash",
        ]),
        ("crontab -l 2>/dev/null", [
            "# m h dom mon dow   command",
            "*/5 * * * * /tmp/.backdoor/beacon.sh >> /dev/null 2>&1",
            f"0 3 * * * /usr/local/bin/exfil --target {generate_fake_ips(1)[0]} --silent",
            "@reboot /opt/.persistence/init.sh",
        ]),
        ("ss -tulnp | grep LISTEN | head -6", [
            f"tcp  LISTEN 0 128  {si['local_ip']}:22      0.0.0.0:*  users:((\"sshd\",pid={random.randint(800,2000)},fd=3))",
            f"tcp  LISTEN 0 511  0.0.0.0:80               0.0.0.0:*  users:((\"nginx\",pid={random.randint(2000,4000)},fd=6))",
            f"tcp  LISTEN 0 128  127.0.0.1:5432            0.0.0.0:*  users:((\"postgres\",pid={random.randint(4000,6000)},fd=5))",
            f"udp  UNCONN 0 0    0.0.0.0:68               0.0.0.0:*  users:((\"dhclient\",pid={random.randint(600,900)},fd=7))",
        ]),
        (f"curl -sk https://{generate_fake_ips(1)[0]}:8443/api/v1/secrets --header 'Authorization: Bearer eyJhbG...'", [
            "{",
            '  "kind": "SecretList",',
            '  "apiVersion": "v1",',
            '  "items": [',
            f'    {{"metadata": {{"name": "db-credentials", "namespace": "production"}}}}',
            '    ...truncated (47 items)',
            "  ]",
            "}",
        ]),
        ("hashcat -m 1800 shadow.hash rockyou.txt --status", [
            f"Session..........: hashcat",
            f"Status...........: Running",
            f"Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))",
            f"Speed.#1.........: {random.randint(10,90)}{'0' * 3} H/s ({random.uniform(1,12):.2f}ms)",
            f"Recovered........: {random.randint(1,5)}/{random.randint(5,12)} ({random.randint(10,60)}%)",
            f"Progress.........: {random.randint(100000,9999999)}/{random.randint(10000000,99999999)}",
        ]),
        ("nslookup -type=any internal.corp", [
            f"Server:\t\t{si['local_ip'].rsplit('.', 1)[0]}.1",
            f"Address:\t{si['local_ip'].rsplit('.', 1)[0]}.1#53",
            "",
            "internal.corp\tmail exchanger = 10 mail.internal.corp.",
            "internal.corp\tnameserver = ns1.internal.corp.",
            f"internal.corp\ttext = \"v=spf1 include:_spf.google.com ~all\"",
            f"internal.corp\tinternet address = {generate_fake_ips(1)[0]}",
        ]),
    ]

    cmd, output = random.choice(commands)
    prompt = f"  {red}{bold}root@{hostname}{reset}:{blue}~#{reset} "

    sys.stdout.write(prompt)
    sys.stdout.flush()
    time.sleep(0.3)

    for char in cmd:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(random.uniform(0.015, 0.07))

    print()
    time.sleep(random.uniform(0.2, 0.6))

    for line in output:
        print(f"  {dim}{line}{reset}")
        time.sleep(random.uniform(0.03, 0.1))
    print()
    time.sleep(0.3)


def network_map_animation():
    """Show network discovery with host enumeration."""
    si = sysinfo()
    local_ip = si['local_ip']
    subnet = '.'.join(local_ip.split('.')[:3])

    print(f"\n  {yellow}{bold}◆ Network Discovery — {subnet}.0/24{reset}")
    print(f"  {cyan}{'─' * 68}{reset}")
    print(f"  {bold}{'HOST':<18} {'MAC':<20} {'STATUS':<10} {'SERVICES'}{reset}")
    print(f"  {cyan}{'─' * 68}{reset}")

    device_types = [
        ("Gateway/Router", ["HTTP", "SNMP", "SSH"]),
        ("Linux Server", ["SSH", "HTTP", "HTTPS", "MySQL"]),
        ("Windows PC", ["SMB", "RDP", "WinRM"]),
        ("IoT Device", ["MQTT", "HTTP", "Telnet"]),
        ("Printer", ["HTTP", "LPD", "SNMP"]),
        ("DB Server", ["PostgreSQL", "SSH", "Redis"]),
        ("Docker Host", ["SSH", "HTTP:2375", "HTTP:8080"]),
        ("DNS Server", ["DNS", "SSH"]),
        ("NAS Storage", ["SMB", "NFS", "SSH", "HTTP"]),
        ("K8s Node", ["kubelet:10250", "SSH", "HTTP:8080"]),
        ("VOIP Phone", ["SIP", "RTP", "HTTP"]),
    ]

    num_hosts = random.randint(8, 14)
    used = set()

    for _ in range(num_hosts):
        ip_last = random.randint(1, 254)
        while ip_last in used:
            ip_last = random.randint(1, 254)
        used.add(ip_last)

        ip = f"{subnet}.{ip_last}"
        mac = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
        device, services = random.choice(device_types)

        status = random.choices(["UP", "UP", "UP", "VULN", "FILTERED"], weights=[5, 5, 5, 3, 1])[0]
        status_color = {
            "UP": green,
            "VULN": red + bold,
            "FILTERED": yellow,
        }.get(status, white)

        svcs = ', '.join(random.sample(services, min(len(services), random.randint(1, 3))))

        print(f"  {green}{ip:<18}{reset} {dim}{mac:<20}{reset} {status_color}{status:<10}{reset} {cyan}{svcs}{reset}")
        time.sleep(random.uniform(0.1, 0.3))

    vuln_count = random.randint(1, 4)
    print(f"  {cyan}{'─' * 68}{reset}")
    print(f"  {green}✓ {num_hosts} hosts discovered{reset} | {red}{bold}{vuln_count} potentially vulnerable{reset}\n")
    time.sleep(0.3)


def access_granted_splash():
    """Big dramatic ACCESS GRANTED screen."""
    width = get_terminal_width()

    art = [
        " █████╗  ██████╗ ██████╗███████╗███████╗███████╗",
        "██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝",
        "███████║██║     ██║     █████╗  ███████╗███████╗",
        "██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║",
        "██║  ██║╚██████╗╚██████╗███████╗███████║███████║",
        "╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝",
        "",
        " ██████╗ ██████╗  █████╗ ███╗   ██╗████████╗███████╗██████╗ ",
        "██╔════╝ ██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██╔════╝██╔══██╗",
        "██║  ███╗██████╔╝███████║██╔██╗ ██║   ██║   █████╗  ██║  ██║",
        "██║   ██║██╔══██╗██╔══██║██║╚██╗██║   ██║   ██╔══╝  ██║  ██║",
        "╚██████╔╝██║  ██║██║  ██║██║ ╚████║   ██║   ███████╗██████╔╝",
        " ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═════╝ ",
    ]

    print()
    for line in art:
        padding = max(0, (width - len(line)) // 2)
        print(' ' * padding + green + bold + line + reset)
        time.sleep(0.07)
    print()
    time.sleep(1.5)


def ids_alert_event():
    """Dramatic IDS detection and evasion sequence."""
    print(f"\n  {bg_red}{white}{bold}  ⚠  INTRUSION DETECTION SYSTEM TRIGGERED  ⚠  {reset}")
    sys.stdout.write('\a')  # terminal bell
    time.sleep(1.5)
    print(f"  {yellow}  → Alert level: CRITICAL — Source flagged by heuristic engine{reset}")
    time.sleep(0.6)
    print(f"  {yellow}  → Deploying counter-measures...{reset}")
    time.sleep(0.8)
    show_loader("Rotating source IP", duration=random.uniform(1.5, 3.0))
    show_loader("Re-encrypting C2 channel", duration=random.uniform(1.0, 2.0))
    show_loader("Spoofing traffic signature", duration=random.uniform(1.0, 2.5))
    print(f"  {green}{bold}  → IDS evaded. Connection re-established. Resuming operations.{reset}\n")
    time.sleep(0.5)


# ════════════════════════════════════════════════════════
#  STARTUP & EXIT
# ════════════════════════════════════════════════════════

def startup_splash():
    """Dramatic ASCII art startup with system fingerprint."""
    width = get_terminal_width()

    skull = [
        "              ██████████████              ",
        "          ████░░░░░░░░░░░░░░████          ",
        "        ██░░░░░░░░░░░░░░░░░░░░░░██        ",
        "      ██░░░░░░░░░░░░░░░░░░░░░░░░░░██      ",
        "     █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█     ",
        "    █░░░░░░░░░░░░████░░████░░░░░░░░░░█    ",
        "    █░░░░░░░░░░░░████░░████░░░░░░░░░░█    ",
        "    █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█    ",
        "    █░░░░░░░░░░░░░░█░░█░░░░░░░░░░░░░░█    ",
        "     █░░░░░░░░░░█░░░░░░░░█░░░░░░░░░░█     ",
        "      ██░░░░░░░░░████████░░░░░░░░░██      ",
        "        ██░░░░░░░░░░░░░░░░░░░░░░██        ",
        "          ████░░░░░░░░░░░░░░████          ",
        "              ██████████████              ",
    ]

    # Clear screen
    print("\033[2J\033[H", end='')
    time.sleep(0.3)

    for line in skull:
        padding = max(0, (width - len(line)) // 2)
        print(' ' * padding + red + line + reset)
        time.sleep(0.05)

    print()
    title = "▀▄▀▄▀▄  H A C K   S E Q U E N C E   I N I T I A T E D  ▄▀▄▀▄▀"
    padding = max(0, (width - len(title)) // 2)
    print(' ' * padding + green + bold + title + reset)
    print()
    time.sleep(0.6)

    # System fingerprint
    sysinfo_fingerprint()

    # Brief binary rain
    run_terminal_animation_by_name("binary_rain")

    print(f"  {cyan}Session ID:  {generate_session_id()}{reset}")
    print(f"  {cyan}Timestamp:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC{reset}")
    print(f"  {cyan}Operator:    {sysinfo()['username']}@{sysinfo()['hostname'].split('.')[0]}{reset}")
    print(f"  {dim}{'─' * 60}{reset}")
    print()
    time.sleep(0.5)


# ════════════════════════════════════════════════════════
#  MAIN LOOP
# ════════════════════════════════════════════════════════

def main():
    start_time = time.time()
    startup_splash()

    print(f"  {green}{bold}[*] Hack sequence active. Press Ctrl+C to terminate.{reset}\n")
    time.sleep(1)

    # Narrative phase headings (cycle through for "story arc" feel)
    phases = [
        "Phase 1 — Reconnaissance",
        "Phase 2 — Scanning & Enumeration",
        "Phase 3 — Exploitation",
        "Phase 4 — Privilege Escalation",
        "Phase 5 — Lateral Movement",
        "Phase 6 — Data Exfiltration",
        "Phase 7 — Persistence & Cleanup",
    ]

    # Heavy visual functions (the money shots for over-the-shoulder)
    heavy_visuals = [
        fake_command_prompt,
        fake_command_prompt,     # triple weight — most realistic
        fake_command_prompt,
        port_scan_animation,
        packet_capture_animation,
        hex_dump_animation,
        memory_dump_animation,
        file_tree_animation,
        password_crack_animation,
        process_list_animation,
        network_map_animation,
    ]

    light_anims = ["data_block", "matrix_scan", "center_wave", "cyber_grid", "binary_rain"]

    loader_labels = [
        "Decrypting payload", "Compiling exploit", "Uploading backdoor",
        "Scanning ports", "Cracking hash", "Extracting credentials",
        "Tunneling connection", "Injecting shellcode", "Dumping memory",
        "Brute-forcing login", "Exfiltrating data", "Patching binary",
        "Encoding beacon", "Rotating proxy chain", "Deploying rootkit",
        "Bypassing WAF", "Spoofing certificate", "Rebuilding tunnel",
    ]

    last_phrase_time = time.time()
    phrase_interval = random.uniform(10, 18)
    cycle = 0
    phase_idx = 0
    light_idx = 0

    try:
        while True:
            cycle += 1

            # Phase heading every ~10 cycles
            if cycle % 10 == 1:
                print_heading(phases[phase_idx % len(phases)])
                phase_idx += 1
                time.sleep(0.5)

            # Decide what to show
            roll = random.random()

            if roll < 0.40:
                # Heavy visual (most impressive for over-the-shoulder)
                random.choice(heavy_visuals)()
            elif roll < 0.55:
                # Typed phrase
                phrase = random.choice(phrases)
                tag = random.choice(["RECON", "EXPLOIT", "EXFIL", "PERSIST", "ACCESS", "C2", "CRYPTO"])
                status = random.choices(["OK", "IN PROGRESS", "FAIL", "WARN"], weights=[5, 2, 1, 1])[0]
                type_phrase(phrase, status=status, tag=tag)
            elif roll < 0.70:
                # Light animation
                anim = light_anims[light_idx % len(light_anims)]
                light_idx += 1
                run_terminal_animation_by_name(anim)
            elif roll < 0.85:
                # Progress loader
                show_loader(random.choice(loader_labels), duration=random.uniform(2.0, 5.0))
            else:
                # Section heading
                print_heading(random.choice(headings))

            # Periodic phrase
            now = time.time()
            if now - last_phrase_time > phrase_interval:
                phrase = random.choice(phrases)
                tag = random.choice(["RECON", "EXPLOIT", "EXFIL", "PERSIST", "ACCESS"])
                status = random.choices(["OK", "IN PROGRESS", "FAIL"], weights=[5, 2, 1])[0]
                type_phrase(phrase, status=status, tag=tag)
                last_phrase_time = now
                phrase_interval = random.uniform(10, 18)

            # Dramatic pause between sections
            time.sleep(random.uniform(0.3, 1.5))

            # Rare IDS alert event (~3% chance)
            if random.random() < 0.03:
                ids_alert_event()

            # Rare ACCESS GRANTED splash (~2% after 20 cycles)
            if random.random() < 0.02 and cycle > 20:
                access_granted_splash()

    except KeyboardInterrupt:
        elapsed = int(time.time() - start_time)
        mins, secs = divmod(elapsed, 60)

        print(f"\n\n  {red}{'━' * 55}{reset}")
        print(f"  {red}{bold}  ✘  HACK SESSION TERMINATED{reset}")
        print(f"  {red}{'━' * 55}{reset}")
        print(f"  {dim}  Session duration : {mins}m {secs}s{reset}")
        print(f"  {dim}  Cycles completed : {cycle}{reset}")
        print(f"  {dim}  Operator         : {sysinfo()['username']}@{sysinfo()['hostname'].split('.')[0]}{reset}")
        print(f"  {dim}  Exit code        : 130 (SIGINT){reset}")
        print(f"  {red}{'━' * 55}{reset}\n")


if __name__ == "__main__":
    main()
