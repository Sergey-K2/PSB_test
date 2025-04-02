import re
from operator import itemgetter


sources_dict = {}
qty_of_sources = 0
severity_dict = {}
ip_addresses_dict = {}
asa_messages_dict = {}

asa_messages_mapping = {
    "106015" : "Deny TCP (no connection)",
    "106021" : "Deny protocol reverse path",
    "106017" : "Deny IP due to Land Attack",
    "419002" : "Received duplicate TCP SYN",
    "733100" : "Object drop rate rate_ID exceeded",
    "305006" : "{outbound static|identity|portmap|regular) translation creation failed for",
    "110002" : "Failed to locate egress interface for protocol",
    "602304" : "An direction tunnel_type SA (SPI=spi) between local_IP and remote_IP (username) has been deleted", 
    "602303" : "IPSEC: An direction tunnel_type SA (SPI=spi) between local_IP and remote_IP (username) has been created",
    "725001" : "Starting SSL handshake with peer-type interface:src-ip/src-port to dst-ip/dst-port for protocol session",
    "725002" : "Device completed SSL handshake with peer-type interface:src-ip/src-port to dst-ip/dst-port for protocol-version session",
    "725007" : "SSL session with peer-type interface:src-ip/src-port to dst-ip/dst-port terminated",
    "713041" : "IKE Initiator: new or rekey Phase 1 or 2, Intf interface_number, IKE Peer IP_address local Proxy Address IP_address, remote Proxy Address IP_address, Crypto map (crypto map tag)",
    "713049" : "Security negotiation complete for tunnel_type type (group_name) Initiator/Responder, Inbound SPI = SPI, Outbound SPI = SPI", 
    "713120" : "PHASE 2 COMPLETED (msgid=msg_id)", 
    "303002" : "FTP connection from src_ifc:src_ip/src_port to dst_ifc:dst_ip/dst_port, user username action file filename", 
    "313005" : "No matching connection for ICMP error message: icmp_msg_info on interface_name interface. Original IP payload: embedded_frame_info icmp_msg_info = icmp src src_interface_name:src_address [([idfw_user | FQDN_string], sg_info)] dst dest_interface_name:dest_address [([idfw_user | FQDN_string], sg_info)] (type icmp_type, code icmp_code) embedded_frame_info = prot src source_address/source_port [([idfw_user | FQDN_string], sg_info)] dst dest_address/dest_port [(idfw_user|FQDN_string), sg_info]", 
    "710003" : "{TCP|UDP} access denied by ACL from source_IP/source_port to interface_name:dest_IP/service",
    "722036" : "Group group User user-name IP IP_address Transmitting large packet length (threshold num).",
    "313001" : "Denied ICMP type=number, code=code from IP_address on interface interface_name",
    "302010" : "connections in use, connections most used",
    "602101" : "PMTU-D packet number bytes greater than effective mtu number dest_addr=dest_address, src_addr=source_address, prot=protocol",
    }

severity_level_mapping = {
    0 : "Emergency",
    1 : "Alert",
    2 : "Critical",
    3 : "Error",
    4 : "Warning",
    5 : "Notice",
    6 : "Informational",
    7 : "Debug"
}

facility_mapping = {
    20 : "Local4",
    21 : "Local5",
    18 : "Local7"
}


ip4_regex_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
ip6_regex_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'

def parse_logs():
    with open("Log4test", "+r") as f, open("report_file.txt", "+w", encoding="utf-8") as rf:
        lines = f.readlines()
        for line in lines:
            type_of_message = int(line[1:5].rstrip(">"))
            facility = type_of_message // 8
            sources_dict.setdefault(facility, 0)
            sources_dict[facility] += 1
            severity = type_of_message % 8
            severity_dict.setdefault(severity, 0)
            severity_dict[severity] += 1
            ip4_addresses = re.findall(ip4_regex_pattern, line)
            ip6_addresses = re.findall(ip6_regex_pattern, line)
            if "%ASA" in line: 
                index = line.find("%ASA") + 7
                message_code = line[index:index+6]
                asa_messages_dict.setdefault(message_code, 0)
                asa_messages_dict[message_code] += 1
            if ip4_addresses:
                for address in ip4_addresses:
                    ip_addresses_dict.setdefault(address, 0)
                    ip_addresses_dict[address] += 1
            if ip6_addresses:
                for address in ip6_addresses:
                    ip_addresses_dict.setdefault(address, 0)
                    ip_addresses_dict[address] += 1
        sorted_ip_addresses_dict = dict(sorted(ip_addresses_dict.items(), key=itemgetter(1), reverse=True))
        sorted_asa_messages_dict = dict(sorted(asa_messages_dict.items(), key=itemgetter(1), reverse=True))
        #print(sorted_ip_addresses_dict)
        print(sorted_asa_messages_dict)
        #print(sources_dict)
        #print(severity_dict)
        for key, value in sources_dict.items():
            rf.write(f"Сообщений от источника (facility) {facility_mapping[key]} - {value}  \n")
        rf.write(f"Всего источников: {len(sources_dict)} \n\n")
        for key, value in severity_dict.items():
            rf.write(f"Количество сообщений типа (severity) {severity_level_mapping[key]} - {value} \n")
        rf.write(f"Всего типов сообщений: {len(severity_dict)} \n\n")
        rf.write("Перечень кодов сообщений Cisco ASA, встречающихся в файле с логами в порядке убывания количества: \n")
        for key, value in sorted_asa_messages_dict.items():
            rf.write(f"{key} {asa_messages_mapping[key]} - {value} \n")
        rf.write(f"Всего кодов сообщений: {len(sorted_asa_messages_dict)} \n\n")
        rf.write("Перечень IP адресов, встречающихся в файле с логами в порядке убывания: \n")
        for key, value in sorted_ip_addresses_dict.items():
            rf.write(f"{key} - {value} \n")
        rf.write(f"Всего ip адресов: {len(sorted_ip_addresses_dict)} \n\n")


if __name__ == "__main__":
    parse_logs()