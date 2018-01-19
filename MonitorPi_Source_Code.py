
from __future__ import print_function
import os, sys
import time
import socket
import _thread
#compatibility
import threading
from struct import *
#import httplib, urllib
import http.client
import urllib.parse

#--------Definition for ThingsSpeak-----------
# TaklBack Definition
# ThingsSpeak -> Apps -> TalkBack
TalkBackID = '15763'
TalkBackAPIKey = 'X0TF1DGNJFOY2G6W'
WKEY = '57U9CEIXT2WF00PC'
headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}


#-------------------- ThingsSpeak----------------

NAME = 'NetworkActivityMonitorPi'
VERSION = '0.3.3.CLI'
VERSIONSTR = '{} v. {}'.format(NAME, VERSION)
#-----------------Variables-------------------------
# global variable declaration for all the counters
#Total Packet Counter Initiation
packet_total = 0
broadcast_packet_total = 0
dhcp_packet_total = 0
dns_packet_total = 0
arp_packet_total = 0
icmp_packet_total = 0
igmp_packet_total = 0
syn_packet_total = 0
http_packet_total = 0
#Total Time Initiation
total_time = 0
#Pacckets Per Second Initiation
total_packet_pps = 0
broadcast_packet_pps = 0
dhcp_packet_pps = 0
dns_packet_pps = 0
arp_packet_pps = 0
icmp_packet_pps = 0
igmp_packet_pps = 0
syn_packet_pps = 0
http_packet_pps = 0
#List for captured packets
list_total = []
list_broadcast = []
list_dhcp = []
list_dns = []
list_arp = []
list_icmp = []
list_igmp = []
list_syn = []
list_http = []
list_mac = []

rawdata = False

#-------------------------------main window---------------------------

def main():
    global rawdata
    print("\n Network Monitoring initiated. \n Log files will be uploaded to the cloud and a text file will be saved at the program location after exit.")
    #  AF_PACKET RAW SOCKET type with GGP protocol to read ethernet frames
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW , socket.ntohs(0x0003))
    except socket.error as msg:
        msg = list(messages)
        print("Socket cant be created !!!\nError code: ", str(messages[0]))
        print("\nMessage: ", messages[1])
        print("\nNetwork Monitoring Tool will now exit.")
        sys.exit()

    #Abort operation by key press
    try:
        ret = packet_loop(s)
    except KeyboardInterrupt:
        print("\n Aborted by user. \n Network Monitoring Terminated \n")
        print("\n Log of the network activity has been saved to a text file at the application location. \n")
        print("\n  \n")
    #-----FOR CLI FILE WRITING------------------
        save_protocol_data ()
        save_mac_data ()
        ret = 1
    return ret


def packet_loop(s):
        # capture packets
    while True:
        packet = s.recvfrom(65565)

        # packet string from tuple
        packet = packet[0]

        # ethernet header bit size set for multiple use
        ethernet_length = 14
        ethernet_header = packet[:ethernet_length]

        # Unpack ethernet header
        eth = unpack('!6s6sH', ethernet_header)
        ethernet_protocol = socket.ntohs(eth[2])

        #Count packets
        packet_counter(mac_address(packet[0:6]), 'mac')

        ethernetinfo = ["Destination MAC: {}".format(mac_address(packet[0:6])),
                        " Source MAC: {}".format(mac_address(packet[6:12])),
                        " Protocol: {}".format(ethernet_protocol)]

        print(" ".join(ethernetinfo))



        # Check for broadcasts
        if mac_address(packet[0:6]) == "FF:FF:FF:FF:FF:FF":
            packet_counter('FF:FF:FF:FF:FF:FF','broadcast')

        # Read ARP packets 0x806
        if ethernet_protocol == 1544:
            # Count ARP packets
            packet_counter(mac_address(packet[0:6]),'arp')

            # Read ARP header 28 bytes
            arp_header = packet[ethernet_length:28 + ethernet_length]

            # Unpack header by information
            arph = unpack('!2s2s1s1s2s6s4s6s4s', arp_header)
            if arph[1] == 8:
                ip_version= 4

            source_mac = arph[5]
            source_ip = socket.inet_ntoa(arph[6])
            destination_mac = arph[7]
            destination_ip = socket.inet_ntoa(arph[8])

            arpinfo = ["\nSource IP : {}".format(source_ip)," Destination IP : {}".format(destination_ip),
                       "\nSource MAC: {}".format(mac_address(source_mac))," Destination MAC: {}".format(mac_address(destination_mac))]
            print(" ".join(arpinfo))

        # Read IP packets = 8 = 0x800
        elif ethernet_protocol == 8:
            # Read IP header 20 bytes
            ip_header = packet[ethernet_length:20 + ethernet_length]

            # Unpack header by information
            ip_header = unpack('!BBHHHBBH4s4s', ip_header)

            ip_version_ihl = ip_header[0]
            ip_version = ip_version_ihl >> 4
            ihl = ip_version_ihl & 0xF

            ip_header_length = ihl * 4
            protocol = ip_header[6]
            source_ip = socket.inet_ntoa(ip_header[8])
            destination_ip = socket.inet_ntoa(ip_header[9])

            ipinfo = ["\nSource IP: {}".format(source_ip)," Destination IP: {}".format(destination_ip),
                      "\nIP v: {}".format(ip_version)," IP Header Length: {}".format(ihl),
                      " Protocol: {}".format(protocol)]
            print(" ".join(ipinfo))

            # TCP protocol header 20 bytes
            if protocol == 6:
                t = ip_header_length + ethernet_length
                tcp_header = packet[t:t + 20]

                # Unpack header by information
                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                #calculate header length
                tcp_header_length = doff_reserved >> 4
                # Read flags to identify SYN good - rst psh
                tcp_flags = tcph[5]
                tcp_fin = tcp_flags >> 0 & 0xF
                tcp_syn = tcp_flags >> 1 & 0xF
                tcp_rst = tcp_flags >> 2 & 0xF
                tcp_psh = tcp_flags >> 3 & 0xF
                tcp_ack = tcp_flags >> 4 & 0xF
                tcp_urg = tcp_flags >> 5 & 0xF

                #Count TCP SYN and HTTP,HTTPS packets
                if (tcp_syn == 1 and tcp_ack == 0):
                    packet_counter(mac_address(packet[0:6]),'syn')
                elif source_port == 80 or source_port == 443:
                    packet_counter(mac_address(packet[0:6]),'http')

                tcpinfo = ["Source Port: {}".format(source_port)," Dest. Port: {}".format(dest_port),
                           "\nSequence Num: {}".format(sequence),"Acknowledgement Num: {}".format(acknowledgement),
                           "\nFIN Flag : {}".format(tcp_fin),"SYN Flag : {}".format(tcp_syn),"RST Flag : {}".format(tcp_rst),
                           "\nPSH Flag : {}".format(tcp_psh),"ACK Flag : {}".format(tcp_ack),"URG Flag : {}".format(tcp_urg)]
                print(" ".join(tcpinfo))
                header_total = ethernet_length + ip_header_length + tcp_header_length * 4
                data_size = len(packet) - header_total

                # packet data extraction
                data = rawdata_decode(packet[header_total:])

                print("Data: {}".format(data))

            # UDP protocol header 8 bytes
            elif protocol == 17:
                u = ip_header_length + ethernet_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                # Unpack header by information
                udph = unpack('!HHHH', udp_header)
                source_port = udph[0]
                destination_port = udph[1]
                length = udph[2]

                #Count UDP DNS and DHCP packets
                if source_port == 53:
                    packet_counter(mac_address(packet[0:6]),'dns')
                elif (source_port == 67 or source_port == 68):
                    packet_counter(mac_address(packet[0:6]),'dhcp')

                udpinfo = ["Source Port: {}".format(source_port),"Dest. Port: {}".format(destination_port),
                           "\nLength: {}".format(length)]
                print(" ".join(udpinfo))

                header_total = ethernet_length + ip_header_length + udph_length
                data_size = len(packet) - header_total

                # packet data extraction
                data = rawdata_decode(packet[header_total:])

                print("Data: {}".format(data))

            # ICMP Packets
            elif protocol == 1:
                # Count ICMP packets
                packet_counter(mac_address(packet[0:6]),'icmp')

                # ICMP protocol header 4 bytes
                u = ip_header_length + ethernet_length
                icmph_length = 4
                icmp_header = packet[u:u + 4]

                # Unpack header by information
                icmph = unpack('!BBH', icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]

                icmpinfo = ["Type: {}".format(icmp_type),"Code: {}".format(code)]
                print(" ".join(icmpinfo))

                header_total = ethernet_length + ip_header_length + icmph_length
                data_size = len(packet) - header_total

                # packet data extraction
                data = rawdata_decode(packet[header_total:])

                print("Data: {}".format(data))

            # IGMP Packets
            elif protocol == 2:
                # Count IGMP packets
                packet_counter(mac_address(packet[0:6]),'igmp')

                # IGMP protocol header 4 bytes
                u = ip_header_length + ethernet_length
                igmph_length = 4
                igmp_header = packet[u:u + 4]
                #IGMP packet counter
                #igmp_packet_total+=1

                # Unpack header by information
                igmph = unpack('!BBH', igmp_header)

                igmp_type = igmph[0]
                code = igmph[1]

                igmpinfo = ["Type: {}".format(igmp_type),"Code: {}".format(code)]
                print(" ".join(igmpinfo))

                header_total = ethernet_length + ip_header_length + icmph_length
                data_size = len(packet) - header_total

                # packet data extraction
                data = rawdata_decode(packet[header_total:])

                print("Data: {}".format(data))

            # Any other TCP protocol packet
            else:
                print("Other IP Protocol packet")

        #Upload packet counter to ThingsSpeak
        params = urllib.parse.urlencode({"field1": broadcast_packet_total,"field2": dhcp_packet_total, "field3":dns_packet_total, "field4":arp_packet_total, "field5":icmp_packet_total, "field6":igmp_packet_total,"field7":syn_packet_total, "field8":http_packet_total,   "key": WKEY})
        conn = http.client.HTTPConnection("api.thingspeak.com:80")
        print( "=====Debug=======" )
        try:
            conn.request("POST", "/update", params, headers)
            response = conn.getresponse()
            print ("Status :", response.status,"Reason:", response.reason)
            data = response.read()
            conn.close()

        except KeyboardInterrupt:
            print("Key interrupt occured")
            break

        except:
            print ("Connection failed")



#-------------------------------Helper functions---------------------------


#Calculate packets per second for all protocols
def calculate_pps ():

    packet_total_old = 0
    broadcast_packet_total_old = 0
    dhcp_packet_total_old = 0
    dns_packet_total_old = 0
    arp_packet_total_old = 0
    icmp_packet_total_old = 0
    igmp_packet_total_old = 0
    syn_packet_total_old = 0
    http_packet_total_old = 0

    global total_time

    global packet_total
    global broadcast_packet_total
    global dhcp_packet_total
    global dns_packet_total
    global arp_packet_total
    global icmp_packet_total
    global igmp_packet_total
    global syn_packet_total
    global http_packet_total

    global packet_total_pps
    global broadcast_packet_pps
    global dhcp_packet_pps
    global dns_packet_pps
    global arp_packet_pps
    global icmp_packet_pps
    global igmp_packet_pps
    global syn_packet_pps
    global http_packet_pps

    threading.Timer(0.5, calculate_pps).start ()

    total_time += 0.5
    print ("hello")
    packet_total_pps = (packet_total - packet_total_old)*2
    broadcast_packet_pps = (broadcast_packet_total - broadcast_packet_total_old)*2
    dhcp_packet_pps = (dhcp_packet_total - dhcp_packet_total_old)*2
    dns_packet_pps = (dns_packet_total - dns_packet_total_old)*2
    arp_packet_pps = (arp_packet_total - arp_packet_total_old)*2
    icmp_packet_pps = (icmp_packet_total - icmp_packet_total_old)*2
    igmp_packet_pps = (igmp_packet_total - igmp_packet_total_old)*2
    syn_packet_pps = (syn_packet_total - syn_packet_total_old)*2
    http_packet_pps = (http_packet_total - http_packet_total_old)*2

    packet_total_old = packet_total
    broadcast_packet_total_old = broadcast_packet_total
    dhcp_packet_total_old = dhcp_packet_total
    dns_packet_total_old = dns_packet_total
    arp_packet_total_old = arp_packet_total
    icmp_packet_total_old = icmp_packet_total
    igmp_packet_total_old = igmp_packet_total
    syn_packet_total_old = syn_packet_total
    http_packet_total_old = http_packet_total

    calculate_pps ()

# Adding packets to counters
def packet_counter(mac_address,protocol_id):
    global list_mac
    global list_syn
    global list_icmp
    global list_igmp
    global list_dns
    global list_dhcp
    global list_http
    global list_arp
    global list_broadcast
    global list_total

    global packet_total
    global broadcast_packet_total
    global dhcp_packet_total
    global dns_packet_total
    global arp_packet_total
    global icmp_packet_total
    global igmp_packet_total
    global syn_packet_total
    global http_packet_total

    list_id = 0

    if protocol_id == 'mac':
        packet_total +=1
        #MAC is missing ,add MAC, add to total
        if mac_address not in list_mac :
            list_mac.append(mac_address)
            list_id = len(list_mac)+1
            list_syn.append(0)
            list_icmp.append(0)
            list_igmp.append(0)
            list_dns.append(0)
            list_dhcp.append(0)
            list_http.append(0)
            list_arp.append(0)
            list_broadcast.append(0)
            list_total.append(1)

        else:
            #MAC is present , add to total
            list_id = list_mac.index(mac_address)
            list_total[list_id] += 1

    #Add specific packet totals
    elif protocol_id =='syn':
        list_id = list_mac.index(mac_address)
        list_syn[list_id] += 1
        syn_packet_total += 1
    elif protocol_id =='icmp':
        list_id = list_mac.index(mac_address)
        list_icmp[list_id] += 1
        icmp_packet_total += 1
    elif protocol_id =='igmp':
        list_id = list_mac.index(mac_address)
        list_igmp[list_id] += 1
        igmp_packet_total += 1
    elif protocol_id =='dns':
        list_id = list_mac.index(mac_address)
        list_dns[list_id] += 1
        dns_packet_total += 1
    elif protocol_id =='dhcp':
        list_id = list_mac.index(mac_address)
        list_dhcp[list_id] += 1
        dhcp_packet_total += 1
    elif protocol_id =='http':
        list_id = list_mac.index(mac_address)
        list_http[list_id] += 1
        http_packet_total += 1
    elif protocol_id =='arp':
        list_id = list_mac.index(mac_address)
        list_arp[list_id] += 1
        arp_packet_total += 1
    elif protocol_id =='broadcast':
        list_id = list_mac.index(mac_address)
        list_broadcast[list_id] += 1
        broadcast_packet_total += 1

    return 0


#Readable time function
def hms_time(S):
    M, S = divmod(S, 60)
    H, M = divmod(M, 60)
    return '%02d:%02d:%02d' % (H, M, S)
    _thread.start_new_thread(hms_time, (S))

#Python 3 raw data conversion
def rawdata_decode(r):
    if rawdata:
        return repr(r)
    if sys.version_info.major == 2:
        return r
    return r.decode('ascii', errors='replace')
    _thread.start_new_thread(rawdata_decode, (r))

#Python 3 MAC address decoding
def mac_address(m):
    a = (m[i] for i in range(6))
    return '{:2x}:{:2x}:{:2x}:{:2x}:{:2x}:{:2x}'.format(*a)
    _thread.start_new_thread(mac_address, (m))


#Python 2 MAC address decoding - crash avoidance
def mac_address_2(m):
    a = tuple(ord(m[i]) for i in range(6))
    return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % a
    _thread.start_new_thread(mac_address_2, (m))

# Write all the protocol packet details to text file
def save_protocol_data ():
    global total_time
    global packet_total
    global broadcast_packet_total
    global dhcp_packet_total
    global dns_packet_total
    global arp_packet_total
    global icmp_packet_total
    global igmp_packet_total
    global syn_packet_total
    global http_packet_total

    global total_packet_pps
    global broadcast_packet_pps
    global dhcp_packet_pps
    global dns_packet_pps
    global arp_packet_pps
    global icmp_packet_pps
    global igmp_packet_pps
    global syn_packet_pps
    global http_packet_pps

    with open('Protocol_Packets_.txt', 'w') as f:
        f.write("Total Packets \t" + str(packet_total) + "\t" + str(total_packet_pps) +
          "\nBroadcast Packets \t" + str(broadcast_packet_total) + "\t" + str(broadcast_packet_pps) +
          "\nDHCP Packets \t" + str(dhcp_packet_total) + "\t" + str(dhcp_packet_pps) +
          "\nDNS Packets \t" + str(dns_packet_total) + "\t" + str(dns_packet_pps) +
          "\nARP Packets \t" + str(arp_packet_total) + "\t" + str(arp_packet_pps) +
          "\nICMP Packets \t" + str(icmp_packet_total) + "\t" + str(icmp_packet_pps) +
          "\nIGMP Packets \t" + str(igmp_packet_total) + "\t" + str(igmp_packet_pps) +
          "\nSYN Packets \t" + str(syn_packet_total) + "\t" + str(syn_packet_pps) +
          "\nHTTP Packets \t" + str(http_packet_total) + "\t" + str(http_packet_pps))


# Write all the protocol packet details to text file
def save_mac_data ():
    global list_total
    global list_broadcast
    global list_dhcp
    global list_dns
    global list_arp
    global list_icmp
    global list_igmp
    global list_syn
    global list_http
    global list_mac

    with open('MAC_Address_list_.txt', 'w') as f:
        lists=[list_mac,list_http,list_syn,list_igmp,list_icmp,
               list_arp,list_dns,list_dhcp,list_broadcast,list_total]
        f.write("MAC\tHTTP\tSYN\tIGMP\tICMP\tARP\tDNS\tDHCP\tBroadcast\tTotal\n")
        for x in zip(*lists):
            f.write("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t{8}\t{9}\n".format(*x))

#Python 2 and Python 3 code compatibility select
if __name__ == '__main__':
    if sys.version_info.major == 2:
        mac_address = mac_address_2

    mainret = main()
    sys.exit(mainret)
