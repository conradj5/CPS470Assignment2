import socket
import dns.resolver


# this function emulates the GetNetworkParams provided to us
def get_default_dns():
    return dns.resolver.get_default_resolver().nameservers[0]


if __name__ == '__main__':
    print(socket.gethostname())
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]
    print(nameserver)
