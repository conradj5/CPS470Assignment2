import socket
import dns.resolver


def get_default_dns():
    return dns.resolver.get_default_resolver()[0]


if __name__ == '__main__':
    print(socket.gethostname())
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]
    print(default.nameservers)