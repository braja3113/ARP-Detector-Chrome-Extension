from scapy.all import*
import scapy.all as scapy

def prs_snf_pkt(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
        omac = mac(packet[scapy.ARP].psrc)
        rmac= packet[scapy.ARP].hwsrc
        if omac!=rmac :
            print("You are under ARP attack. Please block {packet[scapy.ARP].psrc}")

def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=prs_snf_pkt)

def mac(ip):
    arp_req=scapy.ARP(pdst=ip)
    broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_brd=broadcast / arp_req
    list= scapy.srp(arp_req_brd, timeout=5,verbose=False)[0]
    print(list[0][1].hwsrc)

 