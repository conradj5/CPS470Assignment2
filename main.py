import socket
from struct import pack
from dns_test import get_default_dns
import struct
import numpy
import copy
from multiprocessing import Queue
import re
import multiprocessing
from sys import argv


def is_ip(addr):
    return re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").match(addr)


def build_a_packet(url, type):
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
    packet += pack("!H", type)  # Query Type
    packet += pack("!H", 1)  # Query Class
    return packet


def execute_request(inpt):
    if is_ip(inpt):
        inpt = '.'.join(reversed(inpt.split('.'))) + '.in-addr.arpa'
        dns_type = 12
    else:
        dns_type = 1

    packet = build_a_packet(inpt, dns_type)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.bind(('', 0))
    # print("Test Request: " + str(bytes(packet)))
    try:
        sock.sendto(bytes(packet), (get_default_dns(), 53))
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        print("Timeout")
        return []
    sock.close()
    # print("Test Response " + str(data))
    # print("Test Response Headers: " + str(struct.unpack('!HHHHHH', data[:12])))
    ans = parse_resp(bytearray(data), len(packet))
    print(ans)
    return ans


def run(que, outq):
    while que.qsize() > 0 and not que.empty():
        nline = que.get()
        res = execute_request(nline)
        if res and len(res) > 0:
            outq.put(nline + " answers " + str(res))
        else:
            outq.put(nline + " No DNS entry")
        que.task_done()


def test_ptr(byte):
    res = numpy.unpackbits(byte)
    return res[0] == 1 and res[1] == 1


def parse_resp(buffer, len_req):
    # For the header
    data = copy.deepcopy(buffer)
    (id, bitmap, q, a, ns, ar) = struct.unpack("!HHHHHH", buffer[:12])

    # Remove the total length of the inital request from the beginning of response.
    del buffer[:len_req + 2]
    ans = []

    for i in range(a):
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', buffer[:10])
        # print(str((rtype, rclass, ttl, rdlength)))
        del buffer[:10]
        if rtype == 1:
            ip = struct.unpack('!BBBB', buffer[:4])
            del buffer[:4]
            ans.append("%d.%d.%d.%d" % ip)
            del buffer[:2]
        elif rtype == 5 or 12:
            rdata = ''
            count = 0
            while count < rdlength - 1:
                if not test_ptr(buffer[:1]):
                    # determine the number of chars to read
                    num = struct.unpack("!B", buffer[:1])[0]
                    del buffer[:1]
                    if num == 0:
                        del buffer[:2]
                        break
                    # store the value of substring
                    rdata += buffer[:num].decode() + '.'
                    del buffer[:num]
                    count += num
                else:
                    buffer[0] = buffer[0] & int(b'3f', 16)
                    offset = int.from_bytes(buffer[:2], byteorder='big')
                    num = struct.unpack('!B', data[offset:offset+1])[0]
                    while num != 0:
                        rdata += data[offset + 1:offset + num + 1].decode() + '.'
                        offset += num + 1
                        num = struct.unpack('!B', data[offset:offset + 1])[0]
                    del buffer[:2]
                    count += 2
                    break
            del buffer[:2]
            ans.append(rdata)
    return ans


if __name__ == "__main__":
    if len(argv) < 2:
        print("Usage: python3 main.py option:[numthreads, ip, host]")
        quit(1)
    if is_ip(argv[1]) or not argv[1].isnumeric():
        print (is_ip(argv[1]))
        print(argv)
        execute_request(inpt=argv[1])
        quit(0)
    q = Queue()
    outq = Queue()
    with open('dns-in.txt') as file:
        file.readline()
        file.readline()
        for line in file.readlines():
            q.put(line.split('\t')[0])
    procs = []
    for i in range(int(argv[1])):
        p = multiprocessing.Process(target=run, args=(q,outq))
        p.daemon = True
        p.start()
        procs.append(p)
    q.join()
    for p in procs:
        p.join()
    while outq.qsize() > 0:
        print(outq.get())
    print("MAIN PROCESS DONE")