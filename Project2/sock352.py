# CS 352 project part 2
# this is the initial socket library for project 2
# You wil need to fill in the various methods in this
# library

# main libraries
import binascii
import socket as syssock
import struct
import sys
import threading
import time
import os
from random import *
import math

global mutex
mutex = threading.Lock()

# encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages
global sock352portTx
global sock352portRx
# the public and private keychains in hex format
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

# this is the structure of the sock352 packet
sock352HdrStructStr = '!BBBBHHLLQQLL'

# global variables from my part1

FRAGMENTSIZE = 64000

udpPkt_hdr_data = struct.Struct(sock352HdrStructStr)
SOCK352_SYN = 0x1
SOCK352_FIN = 0x2
SOCK352_ACK = 0x4
SOCK352_RESET = 0x8
SOCK352_HAS_OPT = 0x10

PACKET_OPT_INDEX = 0x2


# global variables form part 1 of Anarav Patel and Saurin Shah's code:

PACKET_FLAG_INDEX = 1
PACKET_SEQUENCE_NO_INDEX = 8
PACKET_ACK_NO_INDEX = 9


PACKET_HEADER_LENGTH = struct.calcsize(sock352HdrStructStr)
MAXIMUM_PAYLOAD_SIZE = FRAGMENTSIZE - PACKET_HEADER_LENGTH


def init(UDPportTx, UDPportRx):
    global sock352portTx
    global sock352portRx

    # define the port numebrs to be used. Each socket will connect to the UDPport it is given, and recieve from R

    sock352portTx = int(UDPportTx)
    if sock352portTx < 1 or sock352portTx > 65535:
        sock352portTx = 27182

    sock352portRx = int(UDPportRx)
    if sock352portRx < 1 or sock352portRx > 65535:
        sock352portRx = 27182


# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys

    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ((len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception as e:
            print ("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print ("error: No filename presented")



    return (publicKeys, privateKeys)


class socket:

    def __init__(self):

        self.samSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

        if not self.samSocket:
            print("Failed to set up socket.")
            return
        else:
            print("Socket set up")

        self.samSocket.settimeout(0.2)
        self.connections = []
        self.connected = False
        self.init_seq_no = 0
        self.seq_no = 0
        self.ack_no = 0
        self.next_ack = 0
        self.acks_needed = {}
        self.last_ack_sent = 0
        self.encryption = False
        self.box = None
        self.nonce = None

        # variables used from the answer key for part 1
        self.can_close = False
        self.retransmit = False
        self.last_acked_received = None
        self.data_packets = []
        print("Socket is initialized")

        return

    def bind(self, address):

        # print("Binding!", address[0])
        # bind the UDP socket to the sending port given
        try:
            self.samSocket.bind((address[0], sock352portRx))
        except IOError:
            print("Failed to bind socket")
        print("Socket is bound to", (address[0], sock352portRx))
        return

        return



    #function to set up encryption keys for the connection
    def set_up_encryption(self):

        sk = None
        pk = None

        if not self.box:
            if ("localhost", str(sock352portRx)) in privateKeys:
                sk = privateKeys["localhost", str(sock352portRx)]
            elif ("*", str(sock352portRx)) in privateKeys:
                sk = privateKeys["*", str(sock352portRx)]
            elif ("*", "*") in privateKeys:
                sk = privateKeys["*", "*"]
            elif ("localhost", "*") in privateKeys:
                sk = privateKeys["localhost", "*"]

            (host, port) = self.connections[0]

            if (host, str(port)) in publicKeys:
                pk = publicKeys[host, str(port)]

            if not sk or not pk:
                print("Error decrypting.")
                return None

            #print(sk, pk)

            self.box = Box(sk, pk)
            self.nonce = nacl.utils.random(Box.NONCE_SIZE)


    def connect(self, *args):

        #  args[0] = the same thing that was sent to connect last time, an address and a placeholder
        #  so use sock352Rx again as the port, and just use the host from it
        # example code to parse an argument list (use option arguments if you want)
        global sock352portTx
        global ENCRYPT
        if (len(args) >= 1):
            (host, port) = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encryption = True




        if self.connected:
            print("Error: Already Connected")
            return

        self.samSocket.bind((host, sock352portRx))
        self.init_seq_no = randint(1, math.pow(2, 64) - 1)
        self.ack_no = 0

        syn_packet = self.createPacket(SOCK352_SYN, self.init_seq_no, self.ack_no)
        syn_packet = syn_packet + "The Syn Packet Body"

        # create a loop to send packet and lsiten for acknowledgement back. If there is a timeout, then resend
        got_handshake_ack = False
        while not got_handshake_ack:

            self.samSocket.sendto(syn_packet, (host, sock352portTx))

            try:
                self.samSocket.settimeout(1)
                data, addr = self.samSocket.recvfrom(1024)
                #if (data, addr) == (1, 1):
                    #continue
                # print("Unpacked Header Recieved:", packets.udpPkt_hdr_data.unpack(data))
            except syssock.timeout:
                print("Resending syn_packet to create connection")
                time.sleep(0.1)
                continue

            # if here is reached, then an ack should have been recieved, so check if proper flag and isn
            received = struct.unpack(sock352HdrStructStr, data[:PACKET_HEADER_LENGTH])

            if received[PACKET_ACK_NO_INDEX] != self.init_seq_no + 1 or received[PACKET_FLAG_INDEX] != SOCK352_SYN:
                print("Error receiving ACK from server for connection, will keep trying")
                continue

            got_handshake_ack = True

        # set appropriate states
        # the third part of the handshake will be sent with the first data sent

        self.connected = True
        self.ack_no = received[PACKET_SEQUENCE_NO_INDEX] + 1
        self.seq_no = self.init_seq_no + 1
        self.connections.append((host, sock352portTx))

        if self.encryption :
            self.set_up_encryption()

        print("Connected to Server from client side")

        return

    def listen(self, backlog):
        # listen is not used in this assignments
        pass


    #function to set up decryption keys for the connection
    def set_up_decryption(self):

        sk = None
        pk = None

        if not self.box:
            if ("127.0.0.1", str(sock352portRx)) in privateKeys:
                sk = privateKeys["127.0.0.1", str(sock352portRx)]
            elif ("*", str(sock352portRx)) in privateKeys:
                sk = privateKeys["*", str(sock352portRx)]
            elif ("*", "*") in privateKeys:
                sk = privateKeys["*", "*"]
            elif ("127.0.0.1", "*") in privateKeys:
                sk = privateKeys["127.0.0.1", "*"]
            elif ("localhost", str(sock352portRx)) in privateKeys:
                sk = privateKeys["localhost", str(sock352portRx)]

            (host, port) = self.connections[0]

            if (host, str(port)) in publicKeys:
                pk = publicKeys[host, str(port)]
            elif host == "127.0.0.1" and ("localhost", str(port)) in publicKeys:
                pk = publicKeys["localhost", str(port)]

            if not sk or not pk:
                print("Error decrypting.")
                return None



            self.box = Box(sk, pk)



    def accept(self, *args):
        # example code to parse an argument list (use option arguments if you want)
        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
        # your code goes here

        if self.connected:
            print("Server already connected.")
            return

        while True:

            try:
                data, addr = self.samSocket.recvfrom(1024)
                #if (data, addr) == (1, 1):
                    #continue
            except syssock.timeout:
                time.sleep(0.1)
                continue

            # now that a SYN packet should have been received, check it to make sure it is one
            recv_body = data[PACKET_HEADER_LENGTH:]
            received = struct.unpack(sock352HdrStructStr, data[:PACKET_HEADER_LENGTH])
            if received[PACKET_FLAG_INDEX] != SOCK352_SYN:
                print("Did not accept a syn packet")
                continue
            else:
                # print(recv_body)
                break
            # if here is reached, then it was a syn packet

        self.init_seq_no = randint(1, math.pow(2, 64) - 1)

        # prepare and pack an ACK packet
        ack_pack = self.createPacket(SOCK352_SYN, self.init_seq_no, received[PACKET_SEQUENCE_NO_INDEX] + 1)
        self.seq_no = self.init_seq_no + 1
        ack_pack = ack_pack + "ack_pack body"
        self.last_ack_sent = received[PACKET_SEQUENCE_NO_INDEX] + 1
        # print(addr)
        sent = self.samSocket.sendto(ack_pack, addr)

        # server init_seq no is now recieved init sequence + 1
        # sends this to client
        self.connections.append((addr))
        sock = self
        print("Connected to Client from Server side", self.connections[0])
        if self.encryption :
            self.set_up_decryption()
        return (sock, addr)


    # this is a method used from Anarav Patel and Saurin Shah's answer key code
        #i added the options argument to signal encryption
    def createPacket(self, flags=0x0, sequence_no=0x0, ack_no=0x0, payload_len=0x0, options=0x0):
        return struct.Struct(sock352HdrStructStr).pack \
                (
                0x1,  # version
                flags,  # flags
                options,  # opt_ptr
                0x0,  # protocol
                PACKET_HEADER_LENGTH,  # header_len
                0x0,  # checksum
                0x0,  # source_port
                0x0,  # dest_port
                sequence_no,  # sequence_no
                ack_no,  # ack_no
                0x0,  # window
                payload_len  # payload_len
            )

    # this is a method from Anarav Patel and Saurin Shah's answer key code
        #i added in functionality for encryption, such as accounting for the encryption's extra length,
            #and setting the correct option for encryption
    def create_data_packets(self, buffer):

        # calculates the total packets needed to transmit the entire buffer

        #
        if self.encryption:
            actual = MAXIMUM_PAYLOAD_SIZE - 40
        else :
            actual = MAXIMUM_PAYLOAD_SIZE

        total_packets = len(buffer) / actual

        # if the length of the buffer is not divisible by the maximum payload size,
        # that means an extra packet will need to be sent to transmit the left over data
        # so it increments total packets by 1
        if len(buffer) % actual != 0:
            total_packets += 1

        # sets the payload length to be the maximum payload size
        payload_len = actual

        # iterates up to total packets and creates each packet
        for i in range(0, total_packets):
            # if we are about to construct the last packet, checks if the payload length
            # needs to adjust to reflect the left over size or the entire maximum packet size
            if i == total_packets - 1:
                if len(buffer) % actual != 0:
                    payload_len = len(buffer) % actual

            # creates the new packet with the appropriate header
            if self.encryption :
                new_packet = self.createPacket(flags=0x0,
                                               sequence_no=self.seq_no,
                                               ack_no=self.ack_no,
                                               payload_len=payload_len,
                                               options= 0x01)
            else :
                new_packet = self.createPacket(flags=0x0,
                                               sequence_no=self.seq_no,
                                               ack_no=self.ack_no,
                                               payload_len=payload_len,
                                               options=0x0)
            # consume the sequence and ack no as it was used to create the packet
            self.seq_no += 1
            self.ack_no += 1

            #print(len(buffer[actual * i: actual * i + payload_len]))
            #print(len(self.box.encrypt(buffer[actual * i:
                                                                               #actual * i + payload_len])))

            # attaches the payload length of buffer to the end of the header to finish constructing the packet
            if self.encryption:
                self.data_packets.append(new_packet + self.box.encrypt(buffer[actual * i:
                                                                               actual * i + payload_len]))
            else:
                self.data_packets.append(new_packet + buffer[actual * i:
                                                             actual * i + payload_len])
        return total_packets

    #function used from my part 1, but i simplified it
    def time_acks(self, end):

        while True:

            time.sleep(0.02)

            if 0 in end:
                return

            # if there is a timeout, clear the dictionary and make sure there is a retransmit from the last ack
            mutex.acquire()

            for i in list(self.acks_needed):
                # if it has not been acked, and its been longer than 0.2 seconds
                if i > self.last_acked_received and time.time() - self.acks_needed[i] > 0.2:
                    self.retransmit = True;
                    break;

            # signal a retransmit is needed from the last_ack_recieved
            if self.retransmit:
                self.acks_needed.clear()

            mutex.release()

        return

    #function used from my part 1, but also simplified.
    def recv_acks(self, end):

        while True:
            if 0 in end:
                return

            try:
                d, a = self.samSocket.recvfrom(1024)
                #if (d, a) == (1, 1):
                    #continue
            except syssock.timeout:
                continue

            header = struct.unpack(sock352HdrStructStr, d[:40])

            mutex.acquire()
            if header[PACKET_ACK_NO_INDEX] > self.last_acked_received:
                self.last_acked_received = header[PACKET_ACK_NO_INDEX]
                # print("Got one: ", self.last_acked_received)

            mutex.release()

        return


    def send(self, buffer):
        # your code goes here

        print("Starting to send", len(buffer), " bytes of data")

        self.can_close = False
        end = {}
        self.last_acked_received = 0
        start_seq_no = self.seq_no


        num_packets = self.create_data_packets(buffer)

        starting_index = 0
        total_sent = 0

        # print("num packets", num_packets)

        t1 = threading.Thread(target=self.recv_acks, args=(end,))
        t1.start()

        t2 = threading.Thread(target=self.time_acks, args=(end,))
        t2.start()

        # I reorganized my send loop here based off of the answer key to project 1
        while not self.can_close:

            mutex.acquire()
            if self.last_acked_received == 0:
                starting_index = 0
            else:
                starting_index = self.last_acked_received - start_seq_no

            # print("huh", self.can_close, starting_index, num_packets, self.last_acked_received, self.seq_no)

            if starting_index == num_packets:
                print("All packets have been acked")
                self.can_close = True

            self.retransmit = False
            mutex.release()

            while not self.retransmit and starting_index < num_packets and not self.can_close:
                # print("here: ", self.data_packets[starting_index][PACKET_HEADER_LENGTH:])
                self.samSocket.sendto(self.data_packets[starting_index], self.connections[0])
                total_sent = total_sent + len(self.data_packets[starting_index][PACKET_HEADER_LENGTH:])
                starting_index = starting_index + 1

                self.acks_needed[starting_index - 1 + start_seq_no] = time.time()

        #print(starting_index, self.seq_no)
        #self.seq_no = self.seq_no + starting_index
        end[0] = True

        t2.join()

        t1.join()
        self.data_packets = [];


        return len(buffer)

    def recv(self, nbytes):
        # your code goes here

        print("Starting to receive", nbytes, " bytes of data")
        total_recv = 0
        data = ""



        while total_recv < nbytes:

            try:
                d, a = self.samSocket.recvfrom(FRAGMENTSIZE)
                #if (d, a) == (1, 1):
                    #continue
            except syssock.timeout:
                print("Still waiting to revceive ", nbytes - total_recv, " out of", nbytes)
                continue

            body = d[PACKET_HEADER_LENGTH:]
            header = struct.unpack(sock352HdrStructStr, d[:PACKET_HEADER_LENGTH])

            #print("check;", self.seq_no, header[PACKET_ACK_NO_INDEX])
            # if the received packet is still a syn packet, it means the ack for that was dropped, and resend it
            if header[PACKET_FLAG_INDEX] == SOCK352_SYN:
                print("Resending setup_ack!")
                ack_pack = self.createPacket(SOCK352_SYN, self.init_seq_no, header[PACKET_SEQUENCE_NO_INDEX] + 1)
                self.seq_no = self.init_seq_no + 1
                ack_pack = ack_pack + "ack_pack body"
                self.last_ack_sent = header[PACKET_SEQUENCE_NO_INDEX] + 1
                self.samSocket.sendto(ack_pack, a)
                continue

            # if packet is out of order, and too far forward, resend last ack and discard this one
            if self.seq_no != header[PACKET_ACK_NO_INDEX]:
                print("Packet out of order",)
                ack_pack = self.createPacket(SOCK352_ACK, self.seq_no, self.last_ack_sent)
                ack_pack = ack_pack + "Resent ack " + str(self.last_ack_sent)
                self.samSocket.sendto(ack_pack, a)
                continue

            #see if packet is encrypted
            ec_set = False
            if header[PACKET_OPT_INDEX] == 0x01 :
                ec_set = True
            # if here, it is the right data in the right order
            # add the data, and send the appropriate ack
            self.seq_no = self.seq_no + 1
            ack_pack = self.createPacket(SOCK352_ACK, self.seq_no, self.last_ack_sent + 1)

            self.last_ack_sent = self.last_ack_sent + 1
            ack_pack = ack_pack + "Ack Body " + str(self.last_ack_sent)
            self.samSocket.sendto(ack_pack, a)

            if ec_set :
                #print(body)
                #print(self.box.decrypt(body))
                data = data + self.box.decrypt(body)
            else :
                data = data + body

            total_recv = len(data)

            if total_recv == nbytes:
                break

        return data

    #function to signal to the other end for a connection termination
    def send_close(self, end):

        fin_pack = self.createPacket(SOCK352_FIN, self.seq_no, self.ack_no)
        while True:
            if 0 in end:
                return
            # print("Sent FIN Packet with no", self.seq_no)
            self.samSocket.sendto(fin_pack, self.connections[0])

    #function to recieve a connection termination from the other end
    def recv_close(self, end):

        check1 = 0
        check2 = 0
        while True:
            if 0 in end:
                return
            try:
                d, a = self.samSocket.recvfrom(FRAGMENTSIZE)
                #if (d, a) == (1, 1):
                    #continue
            except syssock.timeout:
                continue

            header = struct.unpack(sock352HdrStructStr, d[:40])
            if header[PACKET_FLAG_INDEX] == 0x0:
                # then this is data, as the last ack was never received on the client side. resend it
                # print("Saving client from being a zombie (as was possibel in last Asst) and resending last ACK!")
                # body = d[40:]
                # print(body)
                ack_pack = self.createPacket(SOCK352_ACK, self.seq_no, self.last_ack_sent)
                ack_pack = ack_pack + "Ack Body " + str(self.last_ack_sent)
                self.samSocket.sendto(ack_pack, a)

            if header[PACKET_FLAG_INDEX] == SOCK352_FIN:
                # then this is the other sides Close signal. Accept it and send an ACK
                print("Received closing signal for connection")
                ack_pack = self.createPacket(SOCK352_ACK, self.seq_no, self.ack_no)
                ack_pack = ack_pack + "Thanks for closing signal"
                self.samSocket.sendto(ack_pack, a)
                check1 = 1;

            if header[PACKET_FLAG_INDEX] == SOCK352_ACK:
                # then this is an ACK to the close signal
                print("My closing signal has been ACKed")
                check2 = 1

            if check1 + check2 == 2:
                # then both a close signal has been received and acked, and an ack has been received for the signal sent
                end[0] = True;
                print("Double Handshake complete for closing")
                # signal to end all threads
                return

    def close(self):
        # your code goes here
        end = {}
        t1 = threading.Thread(target=self.send_close, args=(end,))
        t1.start()
        print("Sending signal to close connection")
        t2 = threading.Thread(target=self.recv_close, args=(end,))
        t2.start()
        # loop to see if all acks have been received and close is signalled. After 5 seconds, end connection
        start = time.time()
        while True:
            if 0 in end:
                break
            else:
                if time.time() - start > 5:
                    end[0] = True
                    print("5 second Timeout")
                    break
                continue

        t1.join()
        t2.join()

        return






