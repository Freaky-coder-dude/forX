# Tester.py
import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import urllib.parse
from contextlib import closing
from typing import Optional, Dict, Tuple
import aiohttp

# ==========================================
# CONFIGURATION
# ==========================================
INPUT_FILE = "config.txt"
OUTPUT_FILE = "working_configs.txt"
TEST_URL = "http://www.gstatic.com/generate_204"
TIMEOUT = 5  # Seconds
CONCURRENCY = 10  # Simultaneous checks
XRAY_BIN_NAME = "xray"  # binary name (xray.exe on windows)

# ==========================================
# UTILS & PARSERS
# ==========================================

def get_free_port():
    """Finds a free TCP port on localhost."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

def safe_base64_decode(s: str) -> bytes:
    """Robust base64 decoder."""
    s = s.strip().replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (-len(s) % 4))

def parse_vmess(link: str) -> Optional[Dict]:
    try:
        b64_part = link[8:]
        config_str = safe_base64_decode(b64_part).decode('utf-8', errors='ignore')
        c = json.loads(config_str)
        
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": c.get("add"),
                    "port": int(c.get("port")),
                    "users": [{
                        "id": c.get("id"),
                        "alterId": int(c.get("aid", 0)),
                        "security": c.get("scy", "auto")
                    }]
                }]
            },
            "streamSettings": {
                "network": c.get("net", "tcp"),
                "security": c.get("tls", "none") if c.get("tls") else "none",
            }
        }
        
        net = outbound["streamSettings"]["network"]
        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": c.get("path", "/"),
                "headers": {"Host": c.get("host", "")}
            }
        elif net == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": c.get("path", "")
            }
            
        if outbound["streamSettings"]["security"] == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": c.get("sni") or c.get("host"),
                "allowInsecure": True
            }
        return outbound
    except Exception:
        return None

def parse_vless(link: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)
        
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [{"id": parsed.username, "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": params.get("type", ["tcp"])[0],
                "security": params.get("security", ["none"])[0]
            }
        }
        
        net = outbound["streamSettings"]["network"]
        sec = outbound["streamSettings"]["security"]
        
        if net == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": params.get("path", ["/"])[0],
                "headers": {"Host": params.get("host", [""])[0]}
            }
        elif net == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": params.get("serviceName", [""])[0]
            }
            
        if sec in ["tls", "reality"]:
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": params.get("sni", [""])[0],
                "fingerprint": params.get("fp", ["chrome"])[0],
                "allowInsecure": True
            }
            if sec == "reality":
                 outbound["streamSettings"]["realitySettings"] = {
                     "publicKey": params.get("pbk", [""])[0],
                     "shortId": params.get("sid", [""])[0],
                     "serverName": params.get("sni", [""])[0],
                     "fingerprint": params.get("fp", ["chrome"])[0]
                 }
        return outbound
    except Exception:
        return None

def parse_trojan(link: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(link)
        params = urllib.parse.parse_qs(parsed.query)
        
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "password": parsed.username
                }]
            },
            "streamSettings": {
                "network": params.get("type", ["tcp"])[0],
                "security": params.get("security", ["tls"])[0]
            }
        }
        
        if outbound["streamSettings"]["security"] == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": params.get("sni", [""])[0] or parsed.hostname,
                "allowInsecure": True
            }
        return outbound
    except Exception:
        return None

def parse_ss(link: str) -> Optional[Dict]:
    try:
        raw = link[5:].split('#')[0]
        if '@' in raw:
            user_part, host_part = raw.split('@', 1)
            method, password = user_part.split(':', 1)
            host, port = host_part.split(':', 1)
        else:
            decoded = safe_base64_decode(raw).decode()
            user_part, host_part = decoded.split('@', 1)
            method, password = user_part.split(':', 1)
            host, port = host_part.split(':', 1)
            
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": int(port),
                    "method": method,
                    "password": password
                }]
            },
            "streamSettings": {"network": "tcp"}
        }
    except Exception:
        return None

def parse_hysteria2(link: str) -> Optional[Dict]:
    try:
        parsed = urllib.parse.urlparse(link.replace("hy2://", "hysteria2://"))
        params = urllib.parse.parse_qs(parsed.query)
        
        return {
            "protocol": "hysteria2",
            "settings": {
                "address": parsed.hostname,
                "port": parsed.port,
                "auth": {
                    "type": "password",
                    "password": parsed.username
                }
            },
            "streamSettings": {
                "network": "udp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": params.get("sni", [""])[0] or parsed.hostname,
                    "allowInsecure": params.get("insecure", ["0"])[0] == "1"
                }
            }
        }
    except Exception:
        return None

def parse_config(link: str) -> Optional[Dict]:
    link = link.strip()
    if link.startswith("vmess://"): return parse_vmess(link)
    if link.startswith("vless://"): return parse_vless(link)
    if link.startswith("trojan://"): return parse_trojan(link)
    if link.startswith("ss://"): return parse_ss(link)
    if link.startswith("hysteria2://") or link.startswith("hy2://"): return parse_hysteria2(link)
    return None

# ==========================================
# TESTER ENGINE
# ==========================================

async def test_proxy(sem: asyncio.Semaphore, link: str, xray_path: str, index: int) -> Tuple[bool, str]:
    async with sem:
        outbound_config = parse_config(link)
        if not outbound_config:
            return False, link

        local_port = get_free_port()
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": local_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            }],
            "outbounds": [outbound_config]
        }
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_config:
            json.dump(config, tmp_config)
            tmp_config_path = tmp_config.name

        proc = None
        try:
            # Start Xray
            proc = subprocess.Popen(
                [xray_path, "-c", tmp_config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            await asyncio.sleep(0.5) # Wait for startup
            
            if proc.poll() is not None:
                return False, link

            proxy_url = f"http://127.0.0.1:{local_port}"
            async with aiohttp.ClientSession() as session:
                start_time = asyncio.get_event_loop().time()
                async with session.get(TEST_URL, proxy=proxy_url, timeout=TIMEOUT, ssl=False) as response:
                    if response.status == 204 or response.status == 200:
                        latency = (asyncio.get_event_loop().time() - start_time) * 1000
                        print(f"[SUCCESS] #{index} Latency: {latency:.0f}ms | {outbound_config['protocol']}")
                        return True, link
                    else:
                        print(f"[FAIL] #{index} Status: {response.status}")
                        return False, link
        except Exception:
            print(f"[FAIL] #{index} Error or Timeout")
            return False, link
        finally:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if os.path.exists(tmp_config_path):
                os.remove(tmp_config_path)

# ==========================================
# MAIN
# ==========================================

async def main():
    print(">>> Masterpiece V2Ray Tester Initialized")
    
    # Locate Xray
    xray_path = shutil.which(XRAY_BIN_NAME)
    if not xray_path:
        cwd_exe = os.path.join(os.getcwd(), "xray.exe" if os.name == 'nt' else "xray")
        if os.path.exists(cwd_exe):
            xray_path = cwd_exe
        else:
            print("[CRITICAL] Xray core not found. Please install Xray-core.")
            return

    # Read File
    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(raw_lines)} configs. Testing with {CONCURRENCY} threads...")

    # Run Tests
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [test_proxy(sem, line, xray_path, i+1) for i, line in enumerate(raw_lines)]
    results = await asyncio.gather(*tasks)

    # Save
    working_configs = [link for success, link in results if success]
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(working_configs))
        
    print("-" * 30)
    print(f"Finished! Working configs: {len(working_configs)} / {len(raw_lines)}")
    print(f"Saved to: {os.path.abspath(OUTPUT_FILE)}")

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())


okay cody, add the support for base64 too cause sometimes the entire txt format may be in base64