import binascii
import socket as syssock
import struct
import sys

#CLASSES TO CREATE A PACKET AND ITS HEADER
    #Packet : can store the header and the body, calls PacketHeader class to deal with header information
    #PacketHeader: stores all of the header states and information
        #Can unpack and pack headers given using the struct.pack call

            #SAM BELUCH, SPB139


#definitions
sock352PktHdrData = '!BBBBHHLLQQLL'
udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
SOCK352_SYN = 0x1
SOCK352_FIN = 0x2
SOCK352_ACK = 0x4
SOCK352_DATA = 0x8



class PacketHeader :

    def __init__ (self, given=None) :
        #intitialize all of the CS352 RDPv1 packet struct fields
            #use the given header and unpack it if needed, if not set all to 0 except the verson (1)
        self.template = udpPkt_hdr_data
        if not given :
            self.version = 0x1
            self.flags = 0x0
            self.opt_ptr = 0x0
            self.protocol = 0x0
            self.header_len = 40 #default header len
            self.checksum = 0x0
            self.source_port = 0x0
            self.dest_port = 0x0
            self.sequence_no = 0x0
            self.ack_no = 0x0
            self.window = 0x0
            self.payload_len = 0x0
            self.packedHead = self.packMe()
        else :
            self.unpackMe(given)

    def unpackMe(self, packed):
            #if the given packed header is too small, return an error
        if len(packed) < 40 :
            print('invalid amount of data in header')
            return

        #unpack the packed header and store the attributes in the Packet header class
        attributes = self.template.unpack(packed)
        self.version = attributes[0]
        self.flags = attributes[1]
        self.opt_ptr = attributes[2]
        self.protocol = attributes[3]
        self.header_len = attributes[4]
        self.checksum = attributes[5]
        self.source_port = attributes[6]
        self.dest_port = attributes[7]
        self.sequence_no = attributes[8]
        self.ack_no = attributes[9]
        self.window = attributes[10]
        self.payload_len = attributes[11]

        return attributes

    def packMe(self) :
        #use the struct.pack call to pack up the header and return it
        packed = self.template.pack(self.version, self.flags, self.opt_ptr, self.protocol, self.header_len, self.checksum, self.source_port, self.dest_port, self.sequence_no, self.ack_no, self.window, self.payload_len)
        return packed


class Packet:

    #initializes the packet with the header and body given.
        #if the header is not given, creates a default one that can be changed on the sock352 end
        #if the body is not given, it is None
    def __init__ (self, header=None, body=None) :
        #store the given header in the packet or create one
        if not header :
            self.header = PacketHeader()
        else :
            self.header = PacketHeader(header)

        #store the given body or have no body
        if not body :
            self.body = None
        else :
            self.body = body

        return

    #packs the packet, by packing the header and appending the body
    def packMe(self):
        self.packed_header = self.header.packMe()

        #if no body, just return the packed header
        #else, return the header plus the body
        if not self.body :
            return self.packed_header
        else :
            return self.packed_header + self.body

    #prints the pacet to check its contents when debugging
    def printMe(self):
        print("Header: ", self.header)
        print("Body: ", self.body)

#only used this main to test if my packet works
def main() :
    s = PacketHeader()
    s = s.unpackMe(s.packedHead)
    print(s)
    return s


if __name__ == '__main__' :
    main()