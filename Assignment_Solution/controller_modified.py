
from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os
import csv

log = core.getLogger()


class VideoSlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)

        # Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
        self.adjacency = defaultdict(lambda:defaultdict(lambda:None))

        '''
        The structure of self.portmap is a four-tuple key and a string value.
        The type is:
        (dpid string, src MAC addr, dst MAC addr, port (int)) -> dpid of next switch
        '''

        self.portmap = {
        # h1 <-- port 80 --> h3
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:01'),
                         EthAddr('00:00:00:00:00:03'), 80): '00-00-00-00-00-03',

                        #  """ Add your mapping logic here"""
                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:01'),
                         EthAddr('00:00:00:00:00:03'), 80): '00-00-00-00-00-04',

                        ('00-00-00-00-00-03', EthAddr('00:00:00:00:00:03'),
                         EthAddr('00:00:00:00:00:01'), 80): '00-00-00-00-00-01',

                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:03'),
                         EthAddr('00:00:00:00:00:01'), 80): '00-00-00-00-00-03',

        # h2 <-- port 22 --> h4
                        ('00-00-00-00-00-01', EthAddr('00:00:00:00:00:02'),
                         EthAddr('00:00:00:00:00:04'), 22): '00-00-00-00-00-02',

                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:02'),
                         EthAddr('00:00:00:00:00:04'), 22): '00-00-00-00-00-04',

                        ('00-00-00-00-00-02', EthAddr('00:00:00:00:00:04'),
                         EthAddr('00:00:00:00:00:02'), 22): '00-00-00-00-00-01',

                        ('00-00-00-00-00-04', EthAddr('00:00:00:00:00:04'),
                         EthAddr('00:00:00:00:00:02'), 22): '00-00-00-00-00-02',
                        }
        log.debug('Enabling Firewall Module __init__')
        self.mac_pair = []
        policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  
        file =  open(policyFile,'rb')
        reader = csv.DictReader(file)
        for row in reader:
            self.mac_pair.append((row['mac_0'], row['mac_1']))
            self.mac_pair.append((row['mac_1'], row['mac_0']))

        log.debug('Firewall policies loaded successfully')

    def _handle_LinkEvent (self, event):
        l = event.link
        sw1 = dpid_to_str(l.dpid1)
        sw2 = dpid_to_str(l.dpid2)

        log.debug ("link %s[%d] <-> %s[%d]",
                   sw1, l.port1,
                   sw2, l.port2)

        self.adjacency[sw1][sw2] = l.port1
        self.adjacency[sw2][sw1] = l.port2


    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        tcpp = event.parsed.find('tcp')

        def install_fwdrule(event,packet,outport):
            msg = of.ofp_flow_mod()
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.actions.append(of.ofp_action_output(port = outport))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        def forward (message = None):
            this_dpid = dpid_to_str(event.dpid)

            if packet.dst.is_multicast:
                flood()
                return
            else:
                log.debug("Got unicast packet for %s at %s (input port %d):",
                          packet.dst, dpid_to_str(event.dpid), event.port)

                try:
                    #  """ Add your logic here""""
                    k = (this_dpid, packet.src, packet.dst, packet.find('tcp').dstport)
                    if not self.portmap.get(k):
                        k = (this_dpid, packet.src, packet.dst, packet.find('tcp').srcport)
                        if not self.portmap.get(k):
                            raise AttributeError

                    ndpid = self.portmap[k]
                    log.debug("install: %s output %d" % (str(k), self.adjacency[this_dpid][ndpid]))
                    install_fwdrule(event,packet,self.adjacency[this_dpid][ndpid])

                except AttributeError:
                    log.debug("packet type has no transport ports, flooding")

                    # flood and install the flow table entry for the flood
                    install_fwdrule(event,packet,of.OFPP_FLOOD)

        # flood, but don't install the rule
        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        forward()


    def _handle_ConnectionUp(self, event):
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)

        for (mac_src, mac_dst) in self.mac_pair:
            match = of.ofp_match()  # obj describing packet header fields & input port to match on
            match.dl_src = EthAddr(mac_src)
            match.dl_dst = EthAddr(mac_dst)
            msg = of.ofp_flow_mod()   # create packet out message
            msg.match = match
            msg.priority = msg_mirror.priority = 42
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(msg) 
    
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Video Slicing module
    '''
    core.registerNew(VideoSlice)