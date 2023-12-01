import pyshark
import requests
import ipaddress

# Function to get the geolocation of an IP address using ipinfo.io
def get_geolocation(ip):
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        response.raise_for_status()
        data = response.json()
        # Format the geolocation information
        geolocation_info = f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
        return geolocation_info
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return "Geolocation not found"

# Prompt the user for the path to the pcap file
pcap_file = input("Enter the path to your pcap file: ")

# Set of unique IPs
unique_ips = set()

# Read the pcap file and extract IP addresses
capture = pyshark.FileCapture(pcap_file)
for packet in capture:
    try:
        if 'IP' in packet:
            unique_ips.add(packet.ip.src)
            unique_ips.add(packet.ip.dst)
    except AttributeError:
        # This packet doesn't have IP layer information
        continue


# Write the IP addresses and their geolocation information to a text file
with open('ip_geolocations.txt', 'w') as f:
    f.write("IP Address,Geolocation Info\n")  # Header for the CSV columns
    for ip in unique_ips:
        # Skip private IP addresses
        if not ipaddress.ip_address(ip).is_private:
            geolocation = get_geolocation(ip)
            f.write(f"{ip},{geolocation}\n")

print("Geolocation lookup complete. Results are saved in ip_geolocations.txt.")
