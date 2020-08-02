#-*- coding: UTF-8 -*-

import logging
from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu import cfg

CONF = cfg.CONF

class test_wpq(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(test_wpq, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.link_to_port = {}
        self.host_or_switch = {}
        self.switch_port_table = {}
        self.name = "wpq"
        self.discover_thread = hub.spawn(self._discover_links)

    #A thread to output the information of topology
    def _discover_links(self):
        while True:
            self.get_topology(None)
            try:
                self.show_topology()
            except Exception as err:
                print ("please input pingall in mininet and wait a memment")
            hub.sleep(5)

    #add entry of table-miss
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handle(self, ev):
        msg = ev.msg
        print (msg)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("switch %s is connected", datapath.id)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath=datapath, priority=0, actions=actions, match=match)

    def add_flow(self, datapath, priority, actions, match, idle_timeout=0, hard_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)

        datapath.send_msg(mod)

    #fill the port of switch imformation
    def create_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

        # print "--------------交换机端口情况---------------"
        # print self.switch_port_table

    #fill the link information
    def create_link_port(self, link_list, host_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[(src.dpid, src.port_no)] = (dst.dpid, dst.port_no)
            self.link_to_port[(dst.dpid, dst.port_no)] = (src.dpid, src.port_no)
            self.host_or_switch[(src.dpid, src.port_no)] = 1
            self.host_or_switch[(dst.dpid, dst.port_no)] = 1

        for host in host_list:
            port = host.port
            self.link_to_port[(port.dpid, port.port_no)] = (host.mac, host.ipv4)
            self.host_or_switch[(port.dpid, port.port_no)] = 2

    #packein message handler (it is useless in this function)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packetin_handler(self, ev):
        # print ev.msg
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        # print pkt.get_protocols
        dpid = msg.datapath.id
        port = msg.match['in_port']
        self.get_topology(None)


    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]
    #monitor the change in link information
    @set_ev_cls(events)
    def get_topology(self, ev):
        self.create_map(get_switch(self.topology_api_app))
        # print get_host(self.topology_api_app)
        # print type(get_host(self.topology_api_app))
        self.create_link_port(get_link(self.topology_api_app), get_host(self.topology_api_app))
        # self.show_topology()

    #some command line output typesetting
    def show_topology(self):
        i = 1
        print ("")
        print ("")
        print ("")
        print ("----------------" * 2, "physical topology", "----------------" * 6)
        for dpid in self.switch_port_table.keys():
            print ("switch%d ----------dpid---------- " % i,)
            for port_no in self.switch_port_table[dpid]:
                print ("-----------port %s-----------" % port_no,)
            print ("")
            print ("        ", "%11d" % dpid ,"%12s" % " ",)
            # # print self.switch_port_table[dpid]
            try:
                for port_no in self.switch_port_table[dpid]:
                    if self.host_or_switch[(dpid, port_no)] == 1:
                        print ("%10s" % "switch", "%d" % self.link_to_port[(dpid, port_no)][0], "     port %d" % self.link_to_port[(dpid, port_no)][1], "  ",)
                    elif self.host_or_switch[(dpid, port_no)] == 2:
                        print ("%s" % "host", "mac: %s" % self.link_to_port[(dpid, port_no)][0],)
                    else:
                        print ("%28s" % "None")

                print ("")
                print ("        ", "%23s" % " ",)
                for port_no in self.switch_port_table[dpid]:
                    if self.host_or_switch[(dpid, port_no)] == 2:
                        print (" ipv4 :", self.link_to_port[(dpid, port_no)][1],)
                    else:
                        print ("%28s" % " ",)
                print
            except Exception as error:
                print ("please input pingall in mininet and wait a momment until it's finished")

            i = i + 1

        print ("------------------" * 8)
        print ("")
        print ("")
        print ("")