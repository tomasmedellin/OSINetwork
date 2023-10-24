import scapy.all as scapy
import socket

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    hosts_list = []
    for element in answered_list:
        host_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        hosts_list.append(host_info)
    return hosts_list

def display_result(hosts_list):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for host in hosts_list:
        print(host["ip"] + "\t\t" + host["mac"])

def port_scan(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port+1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def traffic_analyze():
    packets = scapy.sniff(count=10)
    scapy.wrpcap('temp.pcap', packets)
    for packet in packets:
        print(packet.summary())

if __name__ == "__main__":
    print("1. Network Scanner")
    print("2. Port Scanner")
    print("3. Traffic Analyzer")
    choice = input("Choose an option (1/2/3): ")

    if choice == "1":
        ip_range = input("Enter the IP range (e.g., 192.168.1.1/24): ")
        results = scan(ip_range)
        display_result(results)

    elif choice == "2":
        target_ip = input("Enter the target IP: ")
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))
        open_ports = port_scan(target_ip, start_port, end_port)
        if open_ports:
            print(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
        else:
            print(f"No open ports found on {target_ip}.")

    elif choice == "3":
        traffic_analyze()

    else:
        print("Invalid option.")
