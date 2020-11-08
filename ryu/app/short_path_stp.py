# coding:utf-8

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.lib.packet import ether_types
from ryu.topology import event
from ryu.topology.api import get_link, get_switch

import networkx as nx
import matplotlib.pyplot as plt


class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']
        self.port_forwarded = {}
        # self.port_block = []
        self.topology_api_app = self
        self.network = nx.DiGraph()
        self.paths = {}

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                      {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                      {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                      {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # print('4:in_port:',in_port)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time. mac_to_port saved all forward_port
        self.mac_to_port[dpid][src] = in_port

        out_port = self.get_out_port(datapath, src, dst, in_port)

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # print('out_port:',out_port)
            # print('actions:',actions)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        # print('1:dp:',dp)
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        # print('3:dpid_str:',dpid_str)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        # print('2:dpid_str:',dpid_str)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
        # print('5:ev.port_no:',ev.port_no)
        # print('6:of_State[ev.port_state]:',of_state[ev.port_state])

        self.port_forwarded.setdefault(ev.dp.id, [])
        if of_state[ev.port_state] == 'FORWARD':
            # get forward port
            self.port_forwarded[ev.dp.id].append(ev.port_no)
        # if of_state[ev.port_state] == 'BLOCK':
        #     self.port_block.append({dpid_str:ev.port_no})

    @set_ev_cls(event.EventSwitchEnter, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)

        link_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'attr_dict': {'port': link.src.port_no}})
                 for link in link_list]
        self.network.add_edges_from(links)

        links = [(link.dst.dpid, link.src.dpid, {'attr_dict': {'port': link.dst.port_no}})
                 for link in link_list]
        self.network.add_edges_from(links)

        # print('nodes:', self.network.nodes())
        # print('links:', self.network.edges())
        # print('port_for:', self.port_forwarded)

    def get_out_port(self, datapath, src, dst, in_port):
        '''
        首先根据转发端口删除network里不能转发数据的链路
        self.port_forward-->{dpid:[port]}
        self.netword[dpid]-->{dst_dpid:{'attr_dict':{'port':src_port}}}
                             {src_dpid,{'attr_dict':{'port':dst_port}}}
        seif.get_avai_port(dpid,network) return n_port --> {dpid:[port1,port2,port3...]}
        '''
        dpid = datapath.id
        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(dpid, src, attr_dict={'port': in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})

        self.get_avai_port(dpid, self.network)
        # print('network:',self.network)

        if dst in self.network:
            if dst not in self.paths[src]:
                path = nx.shortest_path(self.network, src, dst)
                self.paths[src][dst] = path

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid) + 1]
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        return out_port

    def get_avai_port(self, dpid, network):
        '''
        self.port_forward-->{dpid:[port]}
        network -->  {dpid: {'attr_dict': {'port': 3}}}
        v --> {'attr_dict':{'port':3}}
        port --> {'port':3}
        n_port --> {dpid:[port1,port2,port3...]}
        '''
        print('network1',network[dpid])
        # for k,v in network[dpid].items():
        #     port = v['attr_dict']['port']
        #     if port not in self.port_forwarded[dpid]:
        #         del network[dpid][k]
        #
        # print('network2',network)
        # return network

