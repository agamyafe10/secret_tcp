#use scapy
from scapy.all import *
import random as rnd
from hlp_funcs import *

#constants
SERVER_IP = '0.0.0.0'#'192.168.1.13'

# recieving data from client
msg = input("enter your message:\n")
num = int(input("enter number of parts for the message:\n"))

#there can't be more parts than letters in the message
if num > len(msg):
    raise ValueError("there mustn't be more parts than length of message")


#THREE WAY HANDSHAKE
def client_handshake(spt, dpt, parts = None):
    syn_segment = TCP(sport=spt, dport=dpt, seq=rnd.randint(1,1000), flags='S')/Raw(load = str(parts))
    syn_packet = IP(dst=SERVER_IP)/syn_segment

    recieved = False
    # running until getting an answer - a SYN ACK packet
    while not recieved:
        send(syn_packet)
        syn_ack_packet = sniff(count=1,lfilter = syn_ack_filter, timeout = 2)# send the first SYN packet
        print(syn_ack_packet.show())
        print(len(syn_ack_packet))
        if len(syn_ack_packet) == 1:
            recieved = True
            print("GOT A SYN ACK PACKET")
    
    # bulding and dending the final ACK packet
    syn_ack_packet = syn_ack_packet[0]
    ack_segment = TCP(sport=spt, dport=dpt, ack=syn_ack_packet['TCP'].seq+1, seq=int(syn_ack_packet['TCP'].ack), flags='A')# after the syn packet sends another ack
    ack_packet = IP(dst=SERVER_IP)/ack_segment
    send(ack_packet)
    print("ACK PACKET SENT!")



# client_handshake(60200, 60100)
 # TRANSFER THE MESSAGE
msg_parts_list = []
parts_length = int(len(msg)/num)
while msg != "":
    msg_parts_list.append(msg[0:parts_length])
    msg = msg[parts_length:]

#send number of parts


for i in range (num):
    # sending each time te tect on a different port
    source_port = rnd.randint(60000, 62225)
    dest_port = rnd.randint(60000, 62225)
    client_handshake(source_port, dest_port, num)
    msg_packet = IP(dst=SERVER_IP)/TCP(sport=source_port, dport=dest_port, seq=rnd.randint(1,1000))/msg_parts_list[num - 1]
    send(msg_packet)
