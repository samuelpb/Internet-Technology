#RUTGERS CS352 INTERNET TECH PROJECT 1
    #TCP IMPLEMENTATION on a UDP PORT
        #SINGLE CONNECTION for PART 1

        #Sam Beluch spb139 170002390


import binascii
import socket as syssock
import struct
import sys
import threading
import packets
import time
import os
from random import *
import math

global mutex
mutex = threading.Lock()



FRAGMENTSIZE = 1024 * 64

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

def init(UDPportTx, UDPportRx):  # initialize your UDP socket here
    global samSocket
    samSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

    if not samSocket :
        print("Failed to set up socket.")
        return
    else :
        print("Socket set up")

    #define the port numebrs to be used. Each socket will connect to the UDPport it is given, and recieve from R
    global UDPportT
    UDPportT = int(UDPportTx)
    if UDPportT < 1 or UDPportT > 65535:
        UDPportT = 27182


    global UDPportR
    UDPportR = int(UDPportRx)
    if UDPportR < 1 or UDPportR > 65535:
        UDPportR = 27182




class socket:

    def __init__(self):
        #need to store data to control the flow of the socket
        self.connections = []
        self.connected = False
        self.init_seq_no = 0
        self.next_seq_no = 0
        self.ack_no = 0
        self.next_ack = 0
        self.acks_needed = {}
        self.last_ack_sent = 0
        print("Socket is initialized")

        return

    def bind(self, address):


        print("Binding!", address[0])
        #bind the UDP socket to the sending port given
        try:
            samSocket.bind((address[0], UDPportR))
        except IOError:
            print("Failed to bind socket")
        print("Socket is bound to", (address[0], UDPportR))
        return


    def connect(self, address):

        #create an initial syn packet to send to the server
        print("Connecting!")
        samSocket.bind((address[0], UDPportR))
        self.init_seq_no = randint(1, math.pow(2, 64)-1)
        self.ack_no = 0
        syn_pack = packets.Packet()
        syn_pack.header.flags = 0x1
        syn_pack.header.sequence_no = self.init_seq_no
        syn_pack.body = "The Syn packet body"
        syn_pack = syn_pack.packMe()

        #print("client_isn", self.init_seq_no)



        #create a loop to send packet and lsiten for acknowledgement back. If there is a timeout, then resend
        while True:

            samSocket.sendto(syn_pack, (address[0], UDPportT))

            try:
                samSocket.settimeout(1)
                data, addr = samSocket.recvfrom(1024)
                if (data, addr) == (1,1) :
                    continue
                #print("Unpacked Header Recieved:", packets.udpPkt_hdr_data.unpack(data))
                break
            except syssock.timeout :
                print("resending syn_packet")
                time.sleep(1)
                continue
            finally :
                samSocket.settimeout(None)

        #if here is reached, then an ack should have been recieved, so check if proper flag and isn
        received = packets.Packet(data[:40], data[40:])

        if received.header.ack_no != self.init_seq_no+1 or received.header.flags != packets.SOCK352_SYN :

            print("Error receiving ACK from server for connection")
            return

        #set appropriate states
        #the third part of the handshake will be sent with the first data sent

        self.connected = True
        self.ack_no = received.header.ack_no -1
        self.next_seq_no = received.header.ack_no
        self.connections.append((address[0], UDPportT))
        print("Connected from client side")

        return

        #client next seq is now the num after the init sequence no
            #will start from there w sequence no



    def listen(self, backlog):
        #no need for this part of the project
        return

    def accept(self):

        #function to accept a connection at the port

        #loops to recieve connections, if it is not a syn packet it will return (-1, -1)
        while True:

            try:
                samSocket.settimeout(0.2)
                data, addr = samSocket.recvfrom(1024)
                if (data, addr) == (1,1) :
                    continue
                break
            except syssock.timeout:

                time.sleep(1)
                continue
            finally :
                samSocket.settimeout(None)

        #now that a SYN packet shoudl have been recieved, check it to make sure it is one
        received = packets.Packet(data[:40], data[40:])
        if received.header.flags != 1 :
            print("Did not accept a syn packet")
            return (-1, -11)

        self.init_seq_no = randint(1, math.pow(2, 64)-1)

        #prepare and pack an ACK packet
        ack_pack = packets.Packet()
        ack_pack.header.flags = 0x1
        ack_pack.header.ack_no = received.header.sequence_no+1
        #print("ack no:", ack_pack.header.ack_no)
        ack_pack.header.sequence_no = self.init_seq_no
        self.next_seq_no = ack_pack.header.ack_no
        ack_pack.body = "ack_pack body"
        self.last_ack_sent = ack_pack.header.ack_no
        ack_pack = ack_pack.packMe()
        print(addr)
        sent = samSocket.sendto(ack_pack, addr)

        #server init_seq no is now recieved init sequence + 1
            #sends this to client

        sock = self
        print("Connected from Server side")
        return (sock, addr)


    def close(self):


        samSocket.close()
        self.acks_needed = {}
        self.ack_no = 0
        self.next_ack = 0
        self.next_seq_no = 0
        self.init_seq_no = 0
        self.connected = False
        self.connections = []

        return

        #close the connection  with the handshake, then close the sockets

        #create a Fin pack, send and wait for ack

        #I can Ask about this tomorrow, as if i should dif between server and client






    def send(self, data):

        print("Starting to send data from sequence no#:", self.next_seq_no)

        end = {}
        total_sent = 0
        counter = 0

        size = 0
        reset = []
        reset.append(0)

        #starts a thread to check the time for ACKS
        t1 = threading.Thread(target= self.timeACKS, args=(self.acks_needed, reset, end))
        t1.start()

        #starts a thread to recv ACKS, and delete them from the list of needed ACKs
        t2 = threading.Thread(target= self.recvACKS, args=(self.acks_needed, samSocket, end))
        t2.start()

        #loop to send the data
        while total_sent<len(data) :

            #time.sleep(1)
            send_pack = packets.Packet()
            counter = counter + 1
            #print(total_sent)
            #if the size is less than the Fragment size, send whatever is left
            if len(data[total_sent:]) + 40 <= FRAGMENTSIZE :
                size = len(data[total_sent:])

                send_pack.body = data[total_sent:]
                send_pack.header.sequence_no = self.next_seq_no
                send_pack.header.payload_len = size
                self.next_ack = self.next_seq_no + size
                self.acks_needed[self.next_seq_no+ size] = time.time()
                #print(send_pack.body, self.acks_needed)
                self.next_seq_no = self.next_seq_no + size

            #else, send the size of the fragment
            else :
                size = FRAGMENTSIZE - 40
                send_pack.body = data[total_sent:(total_sent+FRAGMENTSIZE-40)]

                send_pack.header.payload_len = size

                self.next_ack = self.next_seq_no + size
                self.acks_needed[self.next_ack] = time.time()
                send_pack.header.sequence_no = self.next_seq_no
                self.next_seq_no = self.next_seq_no + size


            #print("Sending:", send_pack.body, total_sent + size)
            send_pack = send_pack.packMe()


            samSocket.sendto(send_pack, self.connections[0])

            total_sent = total_sent + size


            #if whole file has been sent, wait the timeout period to ensure all other acks are recieved
            if total_sent >= len(data) :
                time.sleep(0.3)


            #check to see if there are missing acks, and go back if needed

            mutex.acquire()


            if reset[0] != 0 :

                difference = self.next_seq_no - self.ack_no
                total_sent = total_sent - difference
                #check here to see if it is doin go back N properly
                #print(self.ack_no, "rewinding by", difference, "to", data[total_sent:total_sent+10])
                self.next_seq_no = self.ack_no
                reset[0] = 0
            mutex.release()


        mutex.acquire()
        #send signals to the threads so they end their loops
        end[0] = True
        mutex.release()
        t1.join()
        t2.join()

        return total_sent + counter*40


    #the method to continuously loop and check for timeouts
        #signals a reset if needed that will be caught in the recv function

    def timeACKS(self, dictA, reset, end):

        #print("loop starting")

        while True:
            #loops very fast, so slow it down
            time.sleep(0.02)

            mutex.acquire()

            #signals end of thread
            if 0 in end:
                mutex.release()

                return
            l = {}
            #checks if there is a timeout for any item
            for i in list(dictA):
                if time.time() - dictA[i] > 0.2:

                    reset[0] = i
                    #print("here", reset[0])
                    for j in list(dictA):
                        if j > i :
                            l[j] = 0
                    break
            #removes acks needed for packets that will be resent
            for j in l :
                del dictA[j]

            mutex.release()

        return

    #a method used to recv acks for packets sent
        #if an ack is recieved, all messages up to that point will be ack'd and removed from the need_acks dictionary
    def recvACKS(self, dictA, sam, end):

        while True:
            #if the end of sending is signaled, exit the loop
            if 0 in end:
                return
            try:
                sam.settimeout(0.2)
                d, a = sam.recvfrom(1024)

                if (d,a) == (1,1) :
                    continue

            except syssock.timeout:
                continue

            d = packets.Packet(d[:40], d[40:])

            #check to get rid of all packets now acknowledged
            mutex.acquire()

            if d.header.ack_no > self.ack_no:
                self.ack_no = d.header.ack_no
                #print("ACk for", d.body, d.header.ack_no)

            #remove all acks for packets before the one that was acked, as it could be a cumulitive ack
            l = {}
            for i in list(dictA):
                if i <= d.header.ack_no:
                    l[i] = 0;

            for i in l:
                del dictA[i]
            l = {}
            mutex.release()

        return


    def recv(self, file_len):

        print('Starting to receive', file_len, ' bytes of data')
        total_recv = 0
        data = ""


        while total_recv < file_len :

            #time.sleep(1)

            try:
                samSocket.settimeout(0.2)
                d, a = samSocket.recvfrom(FRAGMENTSIZE)
                if (d, a) == (1,1) :
                    continue

            except syssock.timeout :
                #print("Still waiting to revceive ", file_len, total_recv)
                continue

            received = packets.Packet(d[:40], d[40:])

            #if server thinks it is connected but client isnt, resend the ack to the syn pack recieved
                #connection ACK must have dropped, so resend
                    #just continuing the handshake to ensure a proper 3-way handshake
            if received.header.flags == packets.SOCK352_SYN :
                print("resending setup_ack!")
                ack_pack = packets.Packet()
                ack_pack.header.flags = packets.SOCK352_SYN
                ack_pack.header.ack_no = received.header.sequence_no + 1
                self.last_ack_sent = ack_pack.header.ack_no
                ack_pack.body = "Connected"
                ack_pack = ack_pack.packMe()
                samSocket.sendto(ack_pack, a)
                continue


            #if packet is too far, resend last ack sent and discard this data
            if self.next_seq_no  != received.header.sequence_no :
                #print("Out of order. Discarding:")
                ack_pack = packets.Packet()
                ack_pack.body = "Resent ack" + str(self.last_ack_sent)
                ack_pack.header.ack_no = self.last_ack_sent
                ack_pack = ack_pack.packMe()
                samSocket.sendto(ack_pack, a)
                #print("Not correct order. Will wait for next sent packet and discard this one", self.next_seq_no, received.header.sequence_no)
                #print(self.next_seq_no, received.header.sequence_no)
                continue

            #print("What'd I get", received.body)

            #prepare and send an ACK packet for the received data
            self.next_seq_no = self.next_seq_no + received.header.payload_len
            ack_pack = packets.Packet()
            ack_pack.header.ack_no = received.header.sequence_no + received.header.payload_len
            self.last_ack_sent = ack_pack.header.ack_no
            ack_pack.header.sequence_no = received.header.ack_no+1
            ack_pack.header.flags = packets.SOCK352_ACK
            ack_pack.body = "Thanks for " + received.body
            #print(ack_pack.body)
            ack_pack = ack_pack.packMe()
            samSocket.sendto(ack_pack, a)

            #keep track of the bytes received and the total data
            total_recv = total_recv + len(received.body)
            #print(total_recv, " ", received.body, " ", self.last_ack_sent)
            data = data + received.body

            if total_recv==file_len :
                break


        #print(data)
        return data
