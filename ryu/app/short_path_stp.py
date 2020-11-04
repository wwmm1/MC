#coding:utf-8

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
from ryu.topology.api import get_link,get_switch

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

        #ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time. mac_to_port saved all forward_port
        #需要判断端口是否为转发端口，否则block端口可能会转发（广播）数据
        if src not in self.mac_to_port[dpid].values():
            self.mac_to_port[dpid][src] = in_port

        #判断转发表里的数据是否和mac表里的数据一致,转发表里保存了：dpid+[端口号]，mac表里保存了:dpid+{源地址,端口号}
        #判断转发表所有数据和mac表中所有数据是否一致，首先判断交换机数量
        if len(self.port_forwarded.keys()) == len(self.mac_to_port.keys()):
            forward_port= []
            mac_port = []
            for port in self.port_forwarded.values():
                forward_port += port
            for p in self.mac_to_port.values():
                for port in p.values():
                    mac_port.append(port)
            #转发表里的端口数量和mac表里的端口数量一致，说明，网络达到收敛，可以开始计算路径了。
            if len(forward_port) == len(mac_port):
                print('1')
                # print('forward_port:', forward_port)
                # print('mac_port:', mac_port)
                out_port = self.get_out_port(datapath, src, dst, in_port)

                actions = [parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    print('out_port:', out_port)
                    print('actions:', actions)
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self.add_flow(datapath, 1, match, actions)

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
            else:
                print('2')
                print('forward_port:',self.port_forwarded)
                print('mac_port:',self.mac_to_port)

        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        # print('out_port:',out_port)

        # out_port = self.get_out_port(datapath, src, dst, in_port)

        # actions = [parser.OFPActionOutput(out_port)]
        #
        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     print('out_port:',out_port)
        #     print('actions:',actions)
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        #     self.add_flow(datapath, 1, match, actions)
        #
        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data
        #
        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions, data=data)
        # datapath.send_msg(out)

        # print('forward:', self.port_forwarded)
        # print('block:', self.port_block)

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

        self.port_forwarded.setdefault(dpid_str, [])
        if of_state[ev.port_state] == 'FORWARD':
            # get forward port
            self.port_forwarded[dpid_str].append(ev.port_no)
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

    def get_out_port(self, datapath, src, dst, in_port):
        dpid = datapath.id

        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(dpid, src, attr_dict={'port': in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})
            # print('paths:',self.paths)
            # print('dst:',dst)

        if dst in self.network:
            if dst not in self.paths[src]:
                path = nx.shortest_path(self.network, src, dst)
                self.paths[src][dst] = path
                print('path1:',path)

            path = self.paths[src][dst]
            print('path2:',path)
            next_hop = path[path.index(dpid) + 1]
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        return out_port