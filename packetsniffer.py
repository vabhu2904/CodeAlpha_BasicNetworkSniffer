import socket
import struct

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, offset, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'\tDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\tIPv4 Packet:')
            print(f'\t\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\tProtocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\t\tICMP Packet:')
                print(f'\t\t\tType: {icmp_type}, Code: {code}, Checksum: {checksum}')

            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, offset, data = tcp_segment(data)
                print('\t\tTCP Segment:')
                print(f'\t\t\tSource Port: {src_port}, Destination Port: {dest_port}')
                print(f'\t\t\tSequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'\t\t\tOffset: {offset}')

            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('\t\tUDP Segment:')
                print(f'\t\t\tSource Port: {src_port}, Destination Port: {dest_port}, Length: {size}')

if __name__ == "__main__":
    main()
