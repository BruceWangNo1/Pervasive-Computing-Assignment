#!/usr/bin/python

"""

"""

import inspect
import os
import atexit
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.topo import SingleSwitchTopo
from mininet.node import RemoteController


net = None

class FVTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Create template host, switch, and link
       

        # Create switch nodes
	# example: 
	#	sconfig = {'dpid': "%016x" % 1}
	#	self.addHost('h1', **sconfig)
       

        # Create host nodes
	# example: self.addHost('h1', **hconfig)
        

        # Add switch links
        # Specified to the port numbers to avoid any port number consistency issue       
        # example: 
	#	video_link_config = {'bw':10}
	#	self.addLink('s2', 's1', port1=1, port2=1, **video)
        
        
        info( '\n*** printing and validating the ports running on each interface\n' )
        


def startNetwork():
    info('** Creating Overlay network topology\n')
    topo = FVTopo()
    global net
    net = Mininet(topo=topo, link = TCLink,
                  controller=lambda name: RemoteController(name, ip='pox controller ip'),
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()


    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    if net is not None:
        info('** Tearing down Overlay network\n')
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
