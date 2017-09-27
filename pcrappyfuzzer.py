#!/usr/bin/python
# pcrappyfuzzer.py: a very simple mash-up of Scapy + radamsa to
# extract data from pcap and perform fuzzing ad infinitum.
#
# Originally written for a penetration testing engagement, but modified
# to support the blog post "Fuzzing proprietary protocols with Scapy,
# radamsa and a handful of PCAPs" published in blog.blazeinfosec.com
#
# written by Julio Cesar Fort, Wildfire Labs /// Blaze Information Security
#
# Copyright 2016-2017, Blaze Information Security
# https://www.blazeinfosec.com


from subprocess import Popen, PIPE
import ssl
import socket
import random
import time
import argparse
import os
import sys
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import scapy.all as scapy
except ImportError:
    print "[!] 'scapy' module not found."


VERBOSE = False
PCAP_LOCATION = './test.pcap'
radamsa_bin = '/usr/bin/radamsa'
clients_list = []
servers_list = []
packets_list = []

HOST = '127.0.0.1'
PORT = 443
FUZZ_FACTOR = 50.0

def mutate(payload):
    try:
        radamsa = [radamsa_bin, '-n', '1', '-']
        p = Popen(radamsa, stdin=PIPE, stdout=PIPE)
        mutated_data = p.communicate(payload)[0]
    except:
        print "Could not execute 'radamsa'."
        sys.exit(1)

    return mutated_data


def log_events(log_info, type_event):
    log_msg = "[" + time.ctime() + "]" + "\n" + log_info

    if type_event == "fuzzing":
        try:
            fd = open('fuzz.log', 'a')
        except IOError as err:
            return "[!] Error opening log file: %s" % str(err)

    elif type_event == "error":
        try:
            fd = open('error.log', 'a')
        except IOError as err:
            return "[!] Error opening error file: %s" % str(err)

    else:
        return "[!] '%s' is an unrecognized log event type." % type_event

    if fd:
        fd.write(log_msg)

    return


def main():
    global PCAP_LOCATION, HOST, PORT, FUZZ_FACTOR

    arg = argparse.ArgumentParser(description="A very simple mash-up of Scapy + radamsa to extract data from pcap and perform fuzzing ad infinitum.")
    arg.add_argument("-H", action="store",dest="host", help="Destination IP - Default: 127.0.0.1")
    arg.add_argument("-p", action="store", dest="port", help="Destination Port - Port Default: 443")
    arg.add_argument("-f", action="store", dest="file", help="Input File Location")
    arg.add_argument("-z", action="store", dest="fuzz", help="Fuzz Factor - Default: 50.0")
    arg.add_argument("-s", action="store_true", dest="ssl", default=False, help="Enables SSL")
    arg.add_argument("-v", action="version", version="%(prog)s 1.0")
    
    result = arg.parse_args()
    
    if result.host:
        HOST=result.host
    if result.port:
        try:
            PORT=int(result.port)
        except ValueError:
            print "[!] Option 'port' should be integer"
            exit(1)
    if result.fuzz:
        try:
            FUZZ_FACTOR=int(result.fuzz)
        except ValueError:
            print "[!] Option 'fuzz' should be integer"
            exit(1)
    if result.file:
        PCAP_LOCATION=result.file
    if not os.path.exists(PCAP_LOCATION):
        print "{} file not found. Please check".format(PCAP_LOCATION)
        exit(1)
    pktcounter = 0
    packets = scapy.rdpcap(PCAP_LOCATION)
    random.seed(time.time())

    print "This pcap contains a total of %d packets. Parsing..." % len(packets)

    '''
    Extract the payload of all client->server packets, put them in an
    ordered list for subsequent fuzzing.
    '''
    for pkt in packets:
        '''
        So we can tell since the very begining who is the client and the
        server. We assume the client initiates the connection with a packet
         with SYN as the only flag activated.
        '''
        if pktcounter == 0:
            if pkt['TCP'].sprintf('%TCP.flags%') == 'S':
                clients_list.append(pkt['IP'].src)
                servers_list.append(pkt['IP'].dst)

        if VERBOSE:
            print "Parsing packet #%d" % pktcounter
            print pkt.summary()
        pktcounter += 1

        try:
            if pkt['Raw']:
                '''
                We make sure we only fuzz data traveling from the client to
                the server, in this case is the only thing we're interested
                as we're fuzzing the back-end application
                '''
                if pkt['IP'].src in clients_list:
                    print "Packet #%d has some client->server raw data. Go fuzz!" % pktcounter
                    packet_payload = pkt['Raw']
                    packets_list.append((pktcounter, str(packet_payload)))
        except IndexError:
            continue

    # Infinite loop of mutating packets and them down the wire
    fuzz_iterations = 0

    while True:
        iterations_str = "[+] Fuzzing iteration number #%d" % fuzz_iterations
        print iterations_str

        try:
            fuzz_iterations += 1
            sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockfd.settimeout(5)
            if result.ssl:
                sockfd = ssl.wrap_socket(sockfd)
            sockfd.connect((HOST, PORT))

            for packet in packets_list:
                payload = packet[1]
                if random.random() < FUZZ_FACTOR / 100:
                    payload = mutate(payload)

                iterations_str += "\n" + "--- Payload ---\n" + payload + "\n"
                print payload

                sockfd.send(payload)
                received_buffer = sockfd.recv(2048)

                iterations_str += "\n" + "--- Received ---\n" + received_buffer + "\n"
                print received_buffer

                log_events(iterations_str + '\n', "fuzzing")

                print ""

        except Exception as err:
            error_str = "[!] Error during iteration #%d: %s" % (fuzz_iterations, str(err))
            print error_str
            log_str = error_str + '\n' + iterations_str
            log_events(log_str, "error")
            time.sleep(10)


if __name__ == '__main__':
    main()
