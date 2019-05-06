README.txt

***Sam Beluch spb139 cs352 Asst2***


FILES SUBMITTED:
	sock352.py -- My code for part 2
	README.txt

As I had produced a functional part 1 code, I relied largely on that. However, I did use some functionality from the answer key provided to make my code neater adn more efficient. 

Codes Cited: Sam Beluch sock352 for Asst1
			 Anarav Patel and Saurin Shah : Project1Solutions.py

In Part 2, I slightly reorganized my code (cited sections of code)
	instead of a seperate file for packets, I used the cited functions from the answer key, createPackets and create_data_packets to deal with my packet headers wihtin the same file
	(this also slightly changed my send function slightly to look more similar to the answer key)

*Note* : I still used three threads, one to time the ack for each packet sent, one to receive acks, and one to send data. This was my way of thinking from part 1. I noticed in the answer key, when it receives a packet out of order, rather than retransmitting the last in order ACK, it ignores it. This allows a timeout from the latet acked, instead of indivually timing ACKs.


Functions added for Part 2:
	create_data_packets
	createPacket
		these two were mentioned above

	set_up_encryption: if the files were to be encrypted, then this creates the box and the nonce
	set_up_decryption: creates the server's box to decrypt the data

	send_close : sends a signal to close connection with the other side
	recv_close : waits to receive a signal to close the connection
		These two are threads, and since they are only called after all data has been sent and acked,
			they will time out after 5 seconds and the side will close.

heyyyyy