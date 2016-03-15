Time Streaming Synchronization

[*] Part 1 (eth-sniff.py):

Sniff all network packets and filter for streams.
The sniffed packets are stored inside a dictionary on the manage_pckg thread.
Streams are decided on the stream_decider thread.

Streams are decided according to the:
		
		Streams must be huge flows (TCP or UDP)

        HLS Stream must have: (TCP flows)
            |-> HTTP packets
            |-> HTTP GET for -audio and -video
            |-> HTTP response with content-type: application/vnd.apple.mpegurl
            |-> Has timestamps enabled

Packet streams are categorized in groups:
	-1: Blacklisted: the ip addresses are not part of a stream (live stream)
	 0: Undecided: there is too little packet exchange to decide if it is a stream or not
	 1: Stream: the ip addressess are part of a stream (live stream)

If a stream is decided (-1 or 1) the streaming data are erased; 
If the stream is blacklisted then reseting the data frees memory,
If the stream is a Stream then reseting the data frees memory and makes it ready for the delay and clock calculation.

Only the Undecided packets can get new packets on the dictionaries. For the decided packets check Part 2.
	
	
[*] Part 2 (eth-sniff-p2.py, in progress):

Here we will deal only with the decided Stream packets.
The new packets will not have much data, just the timestamp when they arrive and the clock (if it is set)
Stream structure:
	[time,  clock]...
	
For each new packet, we get the timestamp and we calculate the delay with the last received packet 
The delays are stored on a special list inside of a delays dictionary with keys same as stream
This way we have the delays of more than one streams
	
	
[*] Part 3 (planned):

Do Part 2 for multiple streams and find possible clock ranges (a thread for each stream?)
Run Marzullo's Algorithm to find the most suitable range of clock to update the clock

