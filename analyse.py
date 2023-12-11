from scapy.all import *

# This function prints the raw data to the appropriate .txt file
def get_raw_data(file_path):
    try:
        packets = rdpcap(file_path)

        for packet in packets:
                datafile.write(packet.summary())
                datafile.write("\n")
    
    except Exception as e:
        print(f"Error analyzing pcapng file: {e}")


# This function analyses the .pcapng file and prints the analysis to the appropriate .txt file
def analyze_pcapng(file_path):
    try:
        packets = rdpcap(file_path)

        # Dictionary to store information
        analysis_result = {
            'ip_addresses': {},
            'protocols': {},
            'encryption': set(),
            'port_numbers': set(),
            'services': set()
        }

        for packet in packets:
            # Extract source and destination IP addresses
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Update IP address information
                analysis_result['ip_addresses'][src_ip] = analysis_result['ip_addresses'].get(src_ip, 0) + 1
                analysis_result['ip_addresses'][dst_ip] = analysis_result['ip_addresses'].get(dst_ip, 0) + 1

            # Extract transport layer information (TCP, UDP)
            if TCP in packet:
                protocol = 'TCP'
                port_number = packet[TCP].dport
                service = packet[TCP].sprintf('%s.port%')
            elif UDP in packet:
                protocol = 'UDP'
                port_number = packet[UDP].dport
                service = packet[UDP].sprintf('%s.port%')
            else:
                continue  # Skip non-TCP/UDP packets

            # Update protocol information
            analysis_result['protocols'][protocol] = analysis_result['protocols'].get(protocol, 0) + 1

            # Update port number and service information
            analysis_result['port_numbers'].add(port_number)
            analysis_result['services'].add(service)

            # Check for encryption (you may need to customize this part based on your specific requirements)
            if Raw in packet:
                analysis_result['encryption'].add('Encrypted')

        # Print the analysis result
        file.write("IP Addresses:")
        file.write("\n")
        for ip, count in analysis_result['ip_addresses'].items():
            file.write(f"{ip}: {count} packets")
            file.write("\n")

        file.write("\nProtocols:")
        file.write("\n")
        for protocol, count in analysis_result['protocols'].items():
            file.write(f"{protocol}: {count} packets")
            file.write("\n")

        file.write("\nEncryptions:")
        file.write("\n")
        file.write(", ".join(analysis_result['encryption']))
        file.write("\n")

        file.write("\nPort Numbers:")
        file.write("\n")
        file.write(", ".join(map(str, analysis_result['port_numbers'])))
        file.write("\n")

        file.write("\nServices:")
        file.write("\n")
        file.write(", ".join(analysis_result['services']))
        file.write("\n")

    except Exception as e:
        file.write(f"Error analyzing pcapng file: {e}")


if __name__ == "__main__":
    for i in range (1,12):
        Istring = str(i)
        pcapng_file_path = "capture" + Istring + ".pcapng"

        # Packet Analysis
        filename = "capture" + Istring + "analysis.txt"
        file = open(filename, 'w')
        analyze_pcapng(pcapng_file_path)

        # Raw Data
        datafilename = "capture" + Istring + ".txt"
        datafile = open(datafilename, 'w')
        get_raw_data(pcapng_file_path)

        file.close()
        datafile.close()