from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

print("Starting live capture...")
print("Generating traffic by opening a website...")

sniff(prn=packet_callback, count=10)

print("Capture complete.")