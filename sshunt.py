#!/usr/bin/env python3

"""
sshunt.py - SSH proxy with HASSH firewalling capabilities.
    by Daniel Roberson (daniel@planethacker.net) @dmfroberson

  Basic usage:
  - Edit allow/block lists below to your liking.

  - Configure your sshd to listen on localhost only or a non-standard port
    by setting ListenAddress to 127.0.0.1 or Port to whatever you want.

    - If you opt to use a non-standard port, apply firewall rules accordingly.
      This is an exercise left to the reader if you choose this method.

  - Run this relay on port 22. Forward traffic to non-standard sshd port
    that was configured in the prior step.

  - Incoming connections will be proxied through this. If it is a known bad
    tool, the connection will be dropped.

Example:

# ./sshunt.py 192.168.59.131 22 127.0.0.1 22

"""

# TODO better logging
# TODO drop perms after listen/bind
# TODO daemonize
# TODO config files for HASSHes, firewall rules, etc
# TODO provide HASSH description on events; say what the HASSH is if its denied.

import os
import socket
import sys
import hashlib
import struct

from select import select


def ip_to_long(ip_address):
    """ip_to_long() - Convert human readable IP address to integer"""
    tmp = socket.inet_aton(ip_address)
    return struct.unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    """long_to_ip() - Convert IP integer IP addresses to human-readable string"""
    return socket.inet_ntoa(struct.pack("!L", ip_address))


def network_from_cidr(ip_address, cidrmask):
    """network_from_cidr() - Calculates network address via CIDR mask"""
    ip_addr = ip_to_long(ip_address)
    mask = (0xffffffff << 32 - int(cidrmask)) & 0xffffffff
    return long_to_ip(mask & ip_addr)


def ip_in_network(ip_address, network):
    address, cidrmask = network.split("/")
    network_decimal = ip_to_long(network_from_cidr(address, int(cidrmask)))
    netmask = struct.unpack("!I", struct.pack("!I", (1 << 32) - (1 << (32 - int(cidrmask)))))[0]
    return network_decimal == (ip_to_long(ip_address) & netmask)


class HASSHCollector():
    """HASSHCollector() - HASSH Collector object"""
    def __init__(self, listen_addr, listen_port, relay_addr, relay_port, whitelist=False):
        self.listenfd = None
        self.listen_addr = listen_addr
        self.listen_port = int(listen_port)
        self.relay_addr = relay_addr
        self.relay_port = int(relay_port)

        self.inputs = []
        self.pairs = []

        self.listenfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listenfd.bind((self.listen_addr, self.listen_port))
        except OSError as exc:
            print("[-] bind(): %s" % exc)
            exit(os.EX_USAGE)

        self.listenfd.listen(5)
        self.inputs.append(self.listenfd)

        self.bad_hasshes = [
            "c7b72433b2f67f0bfb36b6e76280cde6", # PuTTY
            "5f52152d3ef8e9d0f7c0fae8b0399689", # Metasploit
            "905ce75ba9c8343782f8d76d938f5ce8", # Hydra
            "55a77ae9728654f1d4240a29287dc296", # Ncrack
            "2dd6531c7e89d3c925db9214711be76a", # Windows OpenSSH
            "38da7a9dfb196c72a7354bb4cdce64d9", # Paramiko-python3
            "602b798d06723866ab820fa24f577e8a", # FileZilla 3.28.0
        ]

        self.good_hasshes = [
            "b12d2871a1189eff20364cf5333619ee", # OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
            "68e0ba85e1a818f7c49ea3f4b849bd15", # OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
            "06046964c022c6407d15a27b12a6a4fb", # OpenSSH_7.6.p1 Ubuntu-4ubuntu0.3
        ]
        self.observed_hasshes = []
        self.good_ips = ["192.168.59.0/24"]
        self.bad_ips = ["192.168.59.1"]


    def add_connection(self):
        """HASSHCollector.add_connection() - add incoming connection"""
        connection, address = self.listenfd.accept()

        bad_ip = False
        for addr in self.bad_ips:
            if "/" in addr:
                if ip_in_network(address[0], addr):
                    bad_ip = True
                    break
            elif addr == address[0]:
                bad_ip = True
                break
        if bad_ip:
            print("[-] Denying incoming connection from bad IP:", address[0])
            connection.close()
            return None

        connection.setblocking(0)
        self.inputs.append(connection)

        # Set up relay
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote.connect((self.relay_addr, self.relay_port))
            remote.setblocking(0)
            self.inputs.append(remote)
            self.pairs.append([connection, remote])
        except ConnectionRefusedError:
            print("[-] Failed to connect to %s:%d" % \
                  (self.relay_addr, self.relay_port))
            self.close_connection(connection)
        return address


    def close_connection(self, connection):
        """HASSHCollector.close_connection() - close socket and clean up"""
        temp_pairs = [pair for pair in self.pairs if connection not in pair]
        self.pairs = temp_pairs
        self.inputs.remove(connection)
        connection.close()


    @staticmethod
    def get_hassh(data):
        """HASSHCollector.get_hassh() - calculate HASSH from a packet"""

        if len(data) < 64:
            return None
        if data[5] != 0x14:
            return None

        offset = 22 # Start of kex data
        kex_len = int.from_bytes(data[offset:offset+4], byteorder="big")
        offset += 4
        kex_methods = data[offset:offset+kex_len].decode("utf-8")
        offset += kex_len

        # Don't need host key algorithms for HASSH
        offset += 4 + int.from_bytes(data[offset:offset+4], byteorder="big")

        enc_ctos_len = int.from_bytes(data[offset:offset+4], byteorder="big")
        offset += 4
        encryption_ctos = data[offset:offset+enc_ctos_len].decode("utf-8")
        offset += enc_ctos_len

        # Don't need encryption stoc for HASSH
        offset += 4 + int.from_bytes(data[offset:offset+4], byteorder="big")

        mac_ctos_len = int.from_bytes(data[offset:offset+4], byteorder="big")
        offset += 4
        mac_ctos = data[offset:offset+mac_ctos_len].decode("utf-8")
        offset += mac_ctos_len

        # Don't need mac stoc for HASSH
        offset += 4 + int.from_bytes(data[offset:offset+4], byteorder="big")

        compression_len = int.from_bytes(data[offset:offset+4], byteorder="big")
        offset += 4
        compression = data[offset:offset+compression_len].decode("utf-8")

        hassh_string = "%s;%s;%s;%s" % \
                       (kex_methods, encryption_ctos, mac_ctos, compression)
        hassh_digest = hashlib.md5(hassh_string.encode("utf-8")).hexdigest()
        return hassh_digest


def main():
    """main() - entry point"""
    try:
        collector = HASSHCollector(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    except IndexError:
        print("[-] Usage: %s <listen addr> <listen port> <relay addr> <relay port>")
        exit(os.EX_USAGE)

    print("[+] Listening on %s:%s -- Relaying to %s:%s" % \
          (collector.listen_addr, collector.listen_port,
           collector.relay_addr, collector.relay_port))

    while True:
        readable, _, exceptions = select(collector.inputs, [], collector.inputs)

        for ready in readable:
            if ready == collector.listenfd:
                # Incoming connection
                address = collector.add_connection()
                if address:
                    print("[+] Connection from", address[0])
                continue

            data = ready.recv(4096)
            if data:
                # TODO this doesn't work right. I don't want to see server banners.
                try:
                    banner = data.decode("utf-8")
                except UnicodeDecodeError:
                    banner = ""
                if banner.startswith("SSH-") \
                   and (ready.getpeername()[0] != collector.relay_addr) \
                   and (ready.getpeername()[0] != collector.relay_port):
                    print("[*] Banner: %s:%d %s" % \
                          (ready.getpeername()[0],
                           ready.getpeername()[1],
                           banner.rstrip()))

                try:
                    hassh = collector.get_hassh(data)
                except UnicodeDecodeError:
                    hassh = None

                if hassh \
                   and hassh in collector.bad_hasshes \
                   and hassh not in collector.good_hasshes:
                    print("[-] Bad HASSH detected from %s: %s" % \
                          (ready.getpeername()[0], hassh))

                    good_ip = False
                    for addr in collector.good_ips:
                        if "/" in addr:
                            if ip_in_network(ready.getpeername()[0], addr):
                                good_ip = True
                                break
                            elif ready.getpeername()[0] == addr:
                                good_ip = True
                                break
                    if good_ip:
                        print("  [+] Allowing good IP %s, despite bad HASSH" % \
                              ready.getpeername()[0])
                    else:
                        print("  [-] Closing connection")
                        collector.close_connection(ready)
                        continue

                if hassh and hassh not in collector.observed_hasshes:
                    collector.observed_hasshes += [hassh]
                    print("[*] New HASSH observed from %s: %s" % \
                          (ready.getpeername()[0], hassh))

                # Relay data...
                for pair in collector.pairs:
                    if pair[0] == ready:
                        pair[1].send(data)
                        break
                    if pair[1] == ready:
                        pair[0].send(data)
                        break
            else:
                print("[-] Caught exception on %s:%d. Closing." % \
                      (ready.getpeername()[0], ready.getpeername()[1]))
                collector.close_connection(ready)

        for exc in exceptions:
            collector.close_connection(exc)


if __name__ == "__main__":
    main()
