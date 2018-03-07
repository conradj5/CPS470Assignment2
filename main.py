import socket
from struct import pack
from dns_test import get_default_dns
import struct
import dns.resolver
import dnslib


def dns_test():
    answers = dns.resolver.query(url, 'A')
    request = dns.message.make_query("yahoo.com", dns.rdatatype.A)
    # m = dns.message.Message()
    print("DNS Request: " + str(request.to_wire()))
    response = dns.query.udp(request, get_default_dns())
    print("DNS Response " + str(response.to_wire()))
    print("DNS Headers " + str(struct.unpack('!HHHHHH', response.to_wire()[:12])))
    print("\nDNSParse: ")
    print(dnslib.DNSRecord.parse(response.to_wire()))


def build_packet(url):
    #  packet = pack("!H", (0 << 15) | (1 << 8) | (0))  # Query Ids (Just 1 for now)
    packet  = pack("!H", 102)
    packet += pack("!H", int('0x0100', 16))  # Flags
    packet += pack("!H", 1)  # Questions
    packet += pack("!H", 0)  # Answers
    packet += pack("!H", 0)  # Authorities
    packet += pack("!H", 0)  # Additional
    for part in url.split('.'):
        packet += pack("B", len(part))
        encoded = str.encode(part)
        for x in range(len(encoded)):
            packet += pack("c", encoded[x:x+1])
    packet += pack("B", 0)  # End of String
    packet += pack("!H", 1)  # Query Type
    packet += pack("!H", 1)  # Query Class
    return packet


def test():
    local_dns = get_default_dns()

    packet = build_packet(url)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bind to arbitrary address and port
    sock.bind(('', 0))
    print("Test Request: " + str(bytes(packet)))
    print("Test Headers " + str(struct.unpack('!HHHHHH', packet[:12])))
    sock.sendto(bytes(packet), (local_dns, 53))
    data, addr = sock.recvfrom(1024)
    print("Test Response " + str(data))
    print("Test Response Headers: " + str(struct.unpack('!HHHHHH', data[:12])))
    sock.close()


if __name__ == "__main__":
    url = "yahoo.com"
    test()
    print()
    dns_test()
