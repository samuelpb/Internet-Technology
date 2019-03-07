README.txt

***Sam Beluch spb139 cs352 Asst1***


The project requires implementing a GO-Back-N protocol over a UDP socket. It is a single connection over a single port, where the client sends the server a file. It works with the most recent server1.py and client1.py posted to test it, as of 3/5.

To do this, I have imported a module for the packets I transmit, called packets. I defined a packet to haveb a header and a body, and to store certain states and information in the header as a TCP packet would.

The server and client are initialized, and the server is binded to the given port. Whne the client connects, it binds to the other port, to make keeping track of where it is very simple.

From there, the connection is set up with a three way handshake, the first two being a part of connect and accept and the third being the first data sent from the client to the server. 

To send the data, the client uses three threads. 

	The first continuously sends the data, breaking it into the packets the size of FRAGMENTSIZE, and adds the sequence numbers to a dictionary with the time sent. 

	The second is a timer to check if any of the sent packets have timed out (after 0.2 seconds) If one does time out, it changes a variable in the first thread. The first thread then rewinds the data being send and resends everything from then on. (GO-Back-N)

	The third recieves the Acknowledgements from the server, and removes the appropriate sequence numbers from the dictionary so they do not time out.


To recieve the data, the server keeps track of the appropriate sequence numbers. If a packet is recieved is out of order, it will ignore the data and resend an acknowledgement of the last in order packet.

Additional Files:
	test.txt -- a long text file I used to test my program
	test1.txt -- the file witten by the server to receive the data
	test2.txt -- a shorter file to send over 
	packets.py -- the packet module
	sockDrop.py -- a module that could be imported instead of socket, and will randomly drop a packet being sent or recieved 10% of the time, and was used to test GO Back N


Difficulties:
	This is the first Python project I have written using threads and sockets, so many difficuties came up
		Also, testing the Go-Back-N protocol as very interesting, and dresulted in many unexpected bugs


