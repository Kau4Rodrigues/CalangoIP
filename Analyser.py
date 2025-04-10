import scapy.all as scapy
import requests
import argparse

def print_banner():
    banner = r"""                                                                                                         
                             
 _____       _                        ___________ 
/  __ \     | |                      |_   _| ___ \
| /  \/ __ _| | __ _ _ __   __ _  ___  | | | |_/ /
| |    / _` | |/ _` | '_ \ / _` |/ _ \ | | |  __/ 
| \__/\ (_| | | (_| | | | | (_| | (_) || |_| |    
 \____/\__,_|_|\__,_|_| |_|\__, |\___/\___/\_|    
                            __/ |                 
                           |___/                                                                                                                              
                                                                                                                        

                ANALYSER IP REPUTATION
          Ferramenta de Análise de Reputação de IP
    """
    print(banner)

def extract_ips_from_pcap(pcap_file):
    try:
        packets = scapy.rdpcap(pcap_file)
        ip_addresses = set()
        
        for packet in packets:
            if packet.haslayer(scapy.IP):
                ip_addresses.add(packet[scapy.IP].src)
                ip_addresses.add(packet[scapy.IP].dst)
        
        return list(ip_addresses)
    except PermissionError:
        print(f"[ERRO] Permissão negada ao tentar acessar o arquivo {pcap_file}. Tente movê-lo para um diretório acessível ou execute o script como Administrador.")
        return []
    except FileNotFoundError:
        print(f"[ERRO] Arquivo {pcap_file} não encontrado. Verifique o caminho e tente novamente.")
        return []

def check_ip_reputation_abuseipdb(ip):
    API_KEY = "2e01403ab3dda96c17ce88ddf7b58116ce655e79768dc131a18403799ed390f373d7e09255b4027b"  
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data["data"]
    else:
        return None

def check_ip_reputation_abusech(ip):
    url = f"https://feodotracker.abuse.ch/browse.php?search={ip}"
    response = requests.get(url)
    if "No results found" in response.text:
        return None
    return f"IP {ip} pode estar associado a C2, verifique: {url}"

def print_results(results):
    for ip, data in results.items():
        print(f"\n IP: {ip}")
        if data.get("abuseConfidenceScore") is not None:
            print(f"    Reputação no AbuseIPDB: {data['abuseConfidenceScore']}%")
        else:
            print("    Não encontrado no AbuseIPDB.")

        if "abusech_result" in data:
            print(f"   ! Possível C2 detectado: {data['abusech_result']}")
        else:
            print("     Não listado na Abuse.ch C2 Tracker.")

def main(pcap_file):
    print_banner()
    ip_list = extract_ips_from_pcap(pcap_file)
    if not ip_list:
        return
    
    results = {}
    print("IPs encontrados no PCAP:")
    for ip in ip_list:
        print(f"Verificando IP: {ip}")
        
        ip_data_abuseipdb = check_ip_reputation_abuseipdb(ip)
        ip_data_abusech = check_ip_reputation_abusech(ip)
        
        results[ip] = {
            "abuseConfidenceScore": ip_data_abuseipdb["abuseConfidenceScore"] if ip_data_abuseipdb else None,
            "abusech_result": ip_data_abusech if ip_data_abusech else None
        }
    
    print_results(results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analisa um PCAP e verifica a reputação de IPs.")
    parser.add_argument("pcap_file", help="Caminho do arquivo PCAP a ser analisado")
    args = parser.parse_args()
    main(args.pcap_file)