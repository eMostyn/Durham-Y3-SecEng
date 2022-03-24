from multiprocessing import Process
from scapy.all import *

import os
import sys
import time

def get_mac(targetip):
    #this function gets and records the MAC address of the network
    pass



class Arper:
    def __init__(self, victim, destination, interface="eth0"):
        #This function initiate the class
        pass

    def run(self):
        #this function runs the overall structure of the attack
        pass


    def poison(self):
        #this function performs the poisoning process
        pass

    def sniff(self, count=200):
        #this function performs the sniffing attack
        pass

    def restore(self):
        #this function restores the network to its usual once the attack is finished
        pass


if __name__ == '__main__':
    (victim, destination, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, destination, interface)
    myarp.run()