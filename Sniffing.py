from scapy.all import sniff, IP, TCP, UDP


def packet_callback(packet):
 if IP in packet:
 ip_src = packet[IP].src
 ip_dst = packet[IP].dst
 protocol = packet[IP].proto

 if TCP in packet:
 protocol_name = "TCP"
 elif UDP in packet:
 protocol_name = "UDP"
 else:
 protocol_name = "Other"

 payload = packet[IP].payload

 print(f"Source IP: {ip_src}")
 print(f"Destination IP: {ip_dst}")
 print(f"Protocol: {protocol_name}")
 print(f"Payload: {payload}")
 print("-" * 50)


def main():
 print("Starting packet sniffer...")
 sniff(prn=packet_callback, store=0)


if __name__ == "__main__":
 main()
