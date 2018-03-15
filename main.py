import copy
import re
import socket
import struct
import time
from multiprocessing import JoinableQueue
from multiprocessing import Process, Lock
from queue import Queue
from struct import pack
from sys import argv

import numpy

from dns_test import get_default_dns

get_time = lambda: int(round(time.time() * 1000))

STATS = {'time': 0, 'num1': 0, 'num2': 0, 'num3': 0}
STATS_LOCK = Lock()


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
    stats = {}
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
    for i in range(1, 4):
        try:
            start = get_time()
            sock.sendto(bytes(packet), (get_default_dns(), 53))
            data, addr = sock.recvfrom(1024)
            stats['time'] = get_time() - start
            stats['num' + str(i)] = 1
            break
        except socket.timeout:
            pass
    sock.close()
    if data:
        print(inpt + ' ' + str(stats) + ' ' + str(parse_resp(bytearray(data), len(packet))))
        (ans, rcode) = parse_resp(bytearray(data), len(packet))
        if rcode != 0:
            stats['time'] = 0
        with STATS_LOCK:
            global STATS
            STATS['time'] = STATS['time'] + stats['time']
        return ans

    return []


def run(in_q, out_q):
    while True:
        nline = in_q.get()
        res = execute_request(nline)
        out_q.put(nline + " answers " + str(res))
        in_q.task_done()


def test_ptr(byte):
    res = numpy.unpackbits(byte)
    return res[0] == 1 and res[1] == 1


def parse_resp(buffer, len_req):
    # For the header
    data = copy.deepcopy(buffer)
    (id, bitmap, q, a, ns, ar) = struct.unpack("!HHHHHH", buffer[:12])

    rcode = bitmap & 15

    if rcode == 3:
        return ['No DNS Entry'], rcode
    if rcode == 2:
        return ['Authoritative DNS server not found'], rcode

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
    return ans, rcode


if __name__ == "__main__":
    if len(argv) < 2:
        print("Usage: python3 main.py option:[numthreads, ip, host]")
        quit(1)
    if is_ip(argv[1]) or not argv[1].isnumeric():
        print(execute_request(inpt=argv[1]))
        quit(0)
    q = JoinableQueue()
    outq = Queue()
    with open('dns-in.txt') as file:
        file.readline()
        file.readline()
        for line in file.readlines():
            q.put(line.split('\t')[0])
    for i in range(int(argv[1])):
        p = Process(target=run, args=(q, outq))
        p.daemon = True
        p.start()
    q.join()
    while outq.qsize() > 0:
        print(outq.get())

    print("MAIN PROCESS DONE")
    print(str(STATS))
