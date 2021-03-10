from scapy.all import *

def syn_filter(packet):
    """filter syn packets for the three way handshake

    Args:
        packet ([type]): [description]

    Returns:
        [type]: [description]
    """
    return TCP in packet and IP in packet and packet[TCP].flags == 'S' and packet[TCP].dport > 60000


def syn_ack_filter(packet):
    return tcp_filter(packet) and packet['TCP'].flags == 'SA' and packet['TCP'].dport > 60000


def filter_by_ip(packet):
    SERVER_IP = '192.168.1.13'
    return int(packet['TCP'].dport) == 40500 #and packet['IP'].dst == SERVER_IP


def ack_filter(packet):
    return TCP in packet and IP in packet and packet[TCP].flags == 'A' and packet[TCP].dport > 60000


def tcp_filter(packet):
    return 'TCP' in packet #and 'IP' in packet


def msg_filter(packet):
    return TCP in packet and IP in packet and packet[TCP].dport > 60000 #and isnumeric(packet[Raw].load)
    