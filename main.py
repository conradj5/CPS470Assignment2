import socket
from struct import pack
from dns_test import get_default_dns
import struct
import numpy
import copy
import sys

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


def test(url):
    local_dns = get_default_dns()

    packet = build_packet(url)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bind to arbitrary address and port
    sock.bind(('', 0))
    sock.sendto(bytes(packet), (local_dns, 53))
    data, addr = sock.recvfrom(1024)
    sock.close()
    parseResp(bytearray(data), len(packet))
    
def testPtr(byte):
    res = numpy.unpackbits(byte)
    return res[0] == 1 and res[1] == 1

def parseResp(buffer, lenReq):
    # For the header
    data = copy.deepcopy(buffer)
    (id, bitmap, q, a, ns, ar) = struct.unpack("!HHHHHH", buffer[:12])

    # Remove the total length of the inital request from the beginning of response.
    del buffer[:lenReq + 2]
    ans = []

    # only need to implement types here to see if a or ptr or cname

    for i in range(a):
        # inconsistency in location by 2 bytes
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', buffer[:10])
        del buffer[:10]
        if rtype == 1: # or type == 1:
            ip = struct.unpack('!BBBB', buffer[:4])
            ans.append("%d.%d.%d.%d" % ip)
            #to adjust for the offset
            del buffer[:4]
        elif rtype == 5:
            rdata = ''
            count = 0
            while count < rdlength - 1:
                offset = 0
                if not testPtr(buffer[:1]):
                    num = struct.unpack("!B", buffer[:1])[0]
                    del buffer[:1]
                    tmp = buffer[:num].decode() + '.'
                    rdata += buffer[:num].decode() + '.'

                    del buffer[:num]
                    count += num
                else:
                    buffer[0] = buffer[0] & int(b'3f', 16)
                    offset = int.from_bytes(buffer[:2], byteorder='big')
                    num = struct.unpack('!B', data[offset:offset+1])[0]
                    while num != 0:
                        tmp = data[offset + 1:offset + num + 1].decode() + '.'
                        rdata += tmp
                        offset += num + 1
                        num = struct.unpack('!B', data[offset:offset + 1])[0]
                    del buffer[:2]
                    count += 2
                    break
            del buffer[:1]
            ans.append(rdata)
        del buffer[:1]
    print(ans)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Useage: main.py <valid domain>')
        exit(1)
    test(sys.argv[1])
