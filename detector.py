import dpkt
import socket
import sys

addresses = {}
scanned_addr = {}

def count_syn_packet(current_address) :
    if current_address in addresses :
        addresses[current_address] = (addresses[current_address][0] + 1, addresses[current_address][1])
    else :
        addresses[current_address] = (1, 0)

def count_syn_ack_packet(current_address) :
    if current_address in addresses :
        addresses[current_address] = (addresses[current_address][0], addresses[current_address][1] + 1)
    else :
        addresses[current_address] = (0, 1)

def who_got_scanned(src_addr, dst_addr) :
    if src_addr in scanned_addr :
        if str(dst_addr) in scanned_addr[src_addr] :
            pass
        else :
            scanned_addr[src_addr].append(str(dst_addr))
            
    else :
        scanned_addr[src_addr] = [str(dst_addr)]

def printPcap(pcap):
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            if (tcp.flags & dpkt.tcp.TH_SYN != 0) and (tcp.flags & dpkt.tcp.TH_ACK == 0) :
                count_syn_packet(src)
                who_got_scanned(src, dst)


            elif ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)) :
                count_syn_ack_packet(dst)

        except:
            pass

    for k1, v1 in addresses.items() :
        if v1[0] >= v1[1] * 3 :
            print("[+] Found Source Host : " + k1)
            print("[+] count (SYN) : " + str(v1[0]))
            print("[+] count (SYN_ACK) : " + str(v1[1]))
            for k2, v2 in scanned_addr.items() :
                if k1 == k2 :
                    for i in range(0, len(v2)) :
                        print("\t[*] Scanned Destination Host : " + str(v2[i]))
            print("==================================================================")


def main() :

    
        if len(sys.argv) < 2 :
            print("Usage : python3 %s <.pcap file>" % sys.argv[0])

        filename = sys.argv[1]

        f = open(filename, 'rb')

        pcap = dpkt.pcap.Reader(f)
        printPcap(pcap)

    
       

if __name__ == '__main__' :
    main()
