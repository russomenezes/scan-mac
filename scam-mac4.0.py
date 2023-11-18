import os
import re
import socket
import threading
from scapy.all import ARP, Ether, srp
import netifaces as network_interfaces
from ipaddress import IPv4Network

def get_all_network_interfaces():
    """
    Obtém as interfaces de rede disponíveis no sistema usando o comando 'ip -br a'.
    Retorna uma lista de nomes de interfaces.
    """
    try:
        command_output = os.popen("ip -br a").read().strip()
        interface_names = re.findall(r'^(\w+)', command_output, re.MULTILINE)
        return interface_names
    except Exception as exception:
        print(f"Erro ao obter interfaces de rede: {exception}")
        return []

def get_ipv4_network_range(interface_name):
    """
    Calcula e retorna a faixa de rede IPv4 da interface especificada.
    """
    try:
        address = network_interfaces.ifaddresses(interface_name)[network_interfaces.AF_INET][0]['addr']
        netmask = network_interfaces.ifaddresses(interface_name)[network_interfaces.AF_INET][0]['netmask']
        network_range = IPv4Network(f"{address}/{netmask}", strict=False)
        return network_range
    except Exception as exception:
        print(f"Erro ao obter a faixa de rede da interface {interface_name}: {exception}")
        return None

def perform_arp_scan(ip_address, found_devices, lock):
    """
    Realiza uma varredura ARP no endereço IP especificado.
    Adiciona as informações dos dispositivos encontrados à lista 'found_devices'.
    """
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=ip_address)
    packet = ethernet_frame/arp_request

    result = srp(packet, timeout=1, verbose=False)[0]

    for sent_packet, received_packet in result:
        try:
            hostname = socket.gethostbyaddr(received_packet.psrc)[0]
        except socket.herror:
            hostname = "Unknown"

        with lock:
            found_devices.append({'ip': received_packet.psrc, 'mac': received_packet.hwsrc, 'hostname': hostname})
def main():
    network_interfaces = get_all_network_interfaces()
    if not network_interfaces:
        print("No network interfaces found.")
        return

    print("Interfaces de rede disponíveis::")
    for index, interface_name in enumerate(network_interfaces, start=1):
        print(f"{index}: {interface_name}")

    choice = input("Digite o numero da rede para inciar o scan: ")
    try:
        selected_interface = network_interfaces[int(choice) - 1]
    except (IndexError, ValueError):
        print("Escolha invalida. Exiting.")
        return

    network_range = get_ipv4_network_range(selected_interface)
    if network_range:
        print(f"Scaneando a rede: {network_range} on interface {selected_interface}")

        devices = []
        threads = []
        thread_lock = threading.Lock()
        for ip_address in network_range.hosts():
            thread = threading.Thread(target=perform_arp_scan, args=(str(ip_address), devices, thread_lock))
            thread.daemon = True
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        print("\n Dispositivos encontrados:")
        print("IP Address" + " " * 10 + "MAC Address" + " " * 15 + "Hostname")
        for device in devices:
            print(f"{device['ip']:16}    {device['mac']:18}    {device['hostname']}")

if __name__ == "__main__":
    main()
