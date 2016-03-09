"""
@author: Nertil Zhuri

Time Streaming

Done:
|->

TODO:
|->

Problems:
|-> None

Updates:
|->

"""

import time
import threading
from scapy.all import *

"""
http://www.secdev.org/projects/scapy/doc/usage.html

http://www.tutorialspoint.com/python/python_dictionary.htm
"""

tcp_buffer  = [] #A list that will store the captured unfiltered packets

"""
These are the Stream dictionaries
The format in which these will be written are:

streams:
(IP-1, IP-2) -> timestamp, end_time, clock (if any), has_timestamps, is_http, get_av, content-type

stream_val:
(IP-1, IP-2) -> is_stream

(IP-1, IP-2) => Will be written as String: 192.168.0.2|77.231.42.33
    |-> Use split("|") to get the two IP's

"""
streams     = {} #Filtered packets into streams  
stream_val  = {} #The values that decide if it is a stream or not


"""
These are the constant indexes of the stored stream
These data fields will be used to determine if the captured packets belong to a stream
And will be determined to compute the time
"""

TIMESTAMP       = 0 #Time the packet is captured
END_TIME        = 1 #Will be used to calculate processing delay of the packet
CLOCK           = 2 #The Date-Time stored on HTTP (if it is enabled)
HAS_TS          = 3 #Boolean: if timestamps option is enabled
IS_HTTP         = 4 #The packet has HTTP layer
GET_AV          = 5 #If IS_HTTP: GET request has -audio and -video request (????)
CONTENT-TYPE    = 6 #If IS_HTTP: Content-Type of the packet is: application/vnd.apple.mpegurl

def printout():
    """
        DEBUGGING FUNCTION
        This thread will printout only streams from time to time
    """
    while True:
        time.sleep(20) #sleep

        for k in stream_val.keys():
            if stream_val(k) == 1:
                kk = k.split("|")
                print "src: "+str(k[0])+" dest: "+str(k[1])

        print "------------------"

def stream_decider():
    """
        This thread will decide if a Stream is a stream or not
    """
          

def manage_pckg(pack):
    """
        This handles the captured packets
        Get the TCP packets and format them to a 'stream' dictionary
        Another thread will decide if the stream IS a stream or not
    """
    if pack.haslayer("TCP"):

        stream_data = [0,0,0,0,0,0,0]

        stream_data[TIMESTAMP] = time.time()
        
        ip1 = pack[IP].src
        ip2 = pack[IP].dest

        ip = str(ip1)+"|"+str(ip2)

        blacklisted = False
        is_stream = 0
        
        if stream_val.has_key(ip):
            #check if it is blacklisted

            is_stream = stream_val[ip]
            
            if stream_val[ip] == -1:
                #ip is blacklisted
                blacklisted = True;
            

        if not blacklisted:
            #TODO: Check if TCP has timestamps enabled
            stream_data[HAS_TS] = False

            if pack.haslayer("HTTP"):
                stream_data[IS_HTTP] = True

                #TODO: Get the apropriate data from the packet
                stream_data[CLOCK] = "-"
                stream_data[GET_AV] = False
                stream_data[CONTENT-TYPE] = False
            else:
                stream_data[IS_HTTP] = False
                stream_data[CLOCK] = "-"
                stream_data[GET_AV] = False
                stream_data[CONTENT-TYPE] = False

            end_t = time.time()
            stream_data[END_TIME] = end_t

            streams[ip] = stream_data #add the data to the dictionary, if it exists python updates it
            stream_val[ip] = is_stream #Whether the stream IS a stream or it is undecided

#call threads:

#call sniffer:
sniff(prn=manage_pckg, store=0)
