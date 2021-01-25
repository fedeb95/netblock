from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
from argparse import ArgumentParser

to_block = []
count = 0
paranoid = False

def process(packet):
    global count,to_block
    if paranoid:
        count += 1
        packet.drop()
        return
    data = packet.get_payload()
    scapy_packet = IP(data)
    if scapy_packet.haslayer(DNS):
        query = str(scapy_packet[DNS].qd.qname)
        for addr in to_block:
            if addr in query:
                print(f'Blocking {query}!')
                count += 1
                packet.drop()
                return
    else:
        if scapy_packet.dst in to_block:
            print(f'Blocking {scapy_packet.dst}!')
            count += 1
            packet.drop()
            return
    packet.accept()

def main():
    global to_blockm, paranoid
    parser = ArgumentParser(description='blocks packets from specified host')
    parser.add_argument('localhost', type=str, help='localhost address, like 192.168.1.0/24')
    parser.add_argument("-p", "--paranoid", dest="paranoid", action="store_true",
                        help="Drop every packet going out of the system")
    parser.add_argument('to_block', type=str, help='destination to block', nargs='?')
    args = parser.parse_args()
    localhost = args.localhost
    to_block = args.to_block
    paranoid = args.paranoid
    print(to_block)

    print(f'Processing all packets from {localhost}')
    os.system(f'iptables -I OUTPUT -s {localhost} -j NFQUEUE --queue-num=1')
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print(f'\nDropped {count} packets to destinations')
    nfqueue.unbind()
    print('Restoring iptables...')
    os.system('iptables -F')
    os.system('iptables -X')

if __name__=='__main__':
    main()
