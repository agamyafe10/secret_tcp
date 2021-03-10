from scapy.all import *
from hlp_funcs import *
import random as rnd
from tcp_secret_server import server_handshake
# from tcp_secret_client import client_handshake


# # starting the three way handsahke listening proccess
# server_handshake()# first handshake
# recieved = False
# # running until getting an answer - a SYN ACK packet
# while not recieved:
#     send(syn_packet)
#     parts_packet = sniff(count=1,lfilter = parts_filter, timeout = 2)# send the first SYN packet
#     print(parts_packet.show())
#     print(len(parts_packet))
#     if len(parts_packet) == 1:
#         recieved = True
#         print("GOT A PART PACKET")
msg = {}
parts_length = server_handshake()
# print("number of parts: " + parts_length)
while True:
    if len(msg) == parts_length:
        break
    server_handshake()
    packets = sniff(count = 1, lfilter = msg_filter)
    packets = packets[0]
    print(packets.show())
    if 'Raw' in packet:
        msg[packets[TCP].seq] = packets[Raw].load
    
# msg = sorted(msg)
for part in msg:
    print(part)
