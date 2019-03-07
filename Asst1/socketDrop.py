#code here will be used to test GO-Back
# N from my own implemented Socket


import socket as syssock
import math
from random import *

timeout = syssock.timeout
AF_INET = syssock.AF_INET
SOCK_DGRAM = syssock.SOCK_DGRAM

class socket :

    def __init__ (self, type1, type2) :
        self.samSocket = syssock.socket(type1, type2)


    def bind(self, a):

        self.samSocket.bind(a)

        return


    def sendto(self, a, b):

        x = randint(0, 10)
        #print(a)
        if x == 2 :
            return
        else :

            self.samSocket.sendto(a, b)
            return

    def settimeout(self, a):

        self.samSocket.settimeout(a)
        return

    def recvfrom (self, a) :

        x = randint(0, 10)
        #print(x)
        if x == 2:
            return (1,1)
        else:
            d, e = self.samSocket.recvfrom(a)
            return (d, e)


    def close (self) :

        self.samSocket.close()

