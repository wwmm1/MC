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
from ryu.lib.packet import arp
from ryu.lib.packet import icmp, ipv4
from ryu.app import simple_switch_13
from ryu.lib.packet import ether_types
from ryu.topology import event
from ryu.topology.api import get_link, get_switch
import networkx as nx
from ast import literal_eval
from zookeeper_server import Zookeeper_Server as zk

import psutil


class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']
        self.port_forwarded = {}
        self.all_port_forwarded = {}
        # self.port_block = {}
        # self.all_port_block = {}
        self.topology_api_app = self
        self.network = nx.DiGraph()

        self.paths = {}
        self.zks = zk('127.0.0.1', '4181')  # connection zk_server
        self.sw_info = []
        self.controller = []
        # self.arp_table = {}

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
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        # icmp_pkt = pkt.get_protocol(icmp.icmp)
        #
        # self.arp_table.setdefault(dpid, {})
        #

        # if icmp_pkt != None:
        #     self._icmp_handler(msg, icmp_pkt)

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # actions = []

        if arp_pkt != None:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if src_ip == '192.168.1.1' and dst_ip == '192.168.1.2':
                if dpid == 2:
                    #match需要从链路层往上依次添加匹配条件
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6, tcp_dst=445)
                    actions = []
                    self.add_flow(datapath, 11111, match, actions)

        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time. mac_to_port saved all forward_port
        self.mac_to_port[dpid][src] = in_port

        out_port = self.get_out_port(datapath, src, dst, in_port)

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
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
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

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

    def get_out_port(self, datapath, src, dst, in_port):
        '''
        首先根据转发端口删除network里不能转发数据的链路,使用self.get_avai_port(dpid,self.network)方法.
        self.port_forward-->{dpid:[port]}
        #self.get_avai_port()返回删除了与阻断端口相连的链路的network
        self.get_avai_port(dpid,self.network) return network --> {dpid:[port1,port2,port3...]}
        '''
        # print('network.edges',self.network.edges)
        dpid = datapath.id
        # 返回删除了阻断端口链路的network
        get_avai_topo = self.get_avai_port(dpid, self.network)

        if dpid in [1, 4] and (src == '00:00:00:00:00:01' or src == '00:00:00:00:00:02'):
            if src not in get_avai_topo:
                get_avai_topo.add_node(src)
                get_avai_topo.add_edge(dpid, src, attr_dict={'port': in_port})
                get_avai_topo.add_edge(src, dpid, attr_dict={'port': 0})
                self.paths.setdefault(src, {})
                if '00:00:00:00:00:03' not in self.paths:
                    self.paths['00:00:00:00:00:03'] = {}
                if '00:00:00:00:00:04' not in self.paths:
                    self.paths['00:00:00:00:00:04'] = {}
        if dpid in [11, 14] and (src == '00:00:00:00:00:03' or src == '00:00:00:00:00:04'):
            if src not in get_avai_topo:
                get_avai_topo.add_node(src)
                get_avai_topo.add_edge(dpid, src, attr_dict={'port': in_port})
                get_avai_topo.add_edge(src, dpid, attr_dict={'port': 0})
                self.paths.setdefault(src, {})
                if '00:00:00:00:00:01' not in self.paths:
                    self.paths['00:00:00:00:00:01'] = {}
                if '00:00:00:00:00:02' not in self.paths:
                    self.paths['00:00:00:00:00:02'] = {}

        # print('get_network.edges:',get_avai_topo.edges)

        self.add_another_edge(dpid, in_port, get_avai_topo)

        self.get_process(dpid, get_avai_topo[dpid], get_avai_topo.nodes,
                         get_avai_topo, datapath.address)

        all_network = self.all_topology(self.controller)

        if not all_network.has_edge(3, 13):
            all_network.add_edge(3, 13, attr_dict={'port': 3})
        if not all_network.has_edge(13, 3):
            all_network.add_edge(13, 3, attr_dict={'port': 3})
        if not all_network.has_edge(6, 16):
            all_network.add_edge(6, 16, attr_dict={'port': 3})
        if not all_network.has_edge(16, 6):
            all_network.add_edge(16, 6, attr_dict={'port': 3})

        # print('all_network.edges:', all_network.edges())
        if dst in all_network:
            if dst not in self.paths[src]:
                # print('0000000000000000000000000000000000000000000000000000000')
                path = nx.shortest_path(all_network, src, dst)
                self.paths[src][dst] = path

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid) + 1]
            out_port = all_network[dpid][next_hop]['attr_dict']['port']
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        return out_port

    def get_avai_port(self, dpid, network):
        '''
        :param dpid:switch id
        :param network:self.network
        :return: 删除了与阻断端口相连的链路的network
        '''
        for k, v in network[dpid].items():
            port = v['attr_dict']['port']
            if len(self.port_forwarded[dpid]) != 0:
                if port not in self.port_forwarded[dpid]:
                    # 需要删除正反向链路,计算最短路径时若有一条链路没删除,将提示A to B 无链路(无法正确连通).
                    if network.has_edge(dpid, k):
                        network.remove_edge(dpid, k)
                    if network.has_edge(k, dpid):
                        network.remove_edge(k, dpid)

        return network

    def add_another_edge(self, dpid, port, network):
        if dpid in [3, 6, 13, 16] and port in self.port_forwarded[dpid]:
            get_dpid_link = get_link(self.topology_api_app, dpid)
            for link in get_dpid_link:
                src_dpid = link.src.dpid
                dst_dpid = link.dst.dpid
                src_port = link.src.port_no
                dst_port = link.dst.port_no
                if dst_port in self.port_forwarded[dst_dpid]:
                    if not network.has_edge(src_dpid, dst_dpid):
                        network.add_edge(src_dpid, dst_dpid, attr_dict={'port': src_port})
                    if not network.has_edge(dst_dpid, src_dpid):
                        network.add_edge(dst_dpid, src_dpid, attr_dict={'port': dst_port})

    def get_process(self, dpid, link, nodes, edges, switch_address_port):
        switch_ip, switch_port = switch_address_port  # get switch ip and port
        # get local_host all process
        all_process = psutil.net_connections()
        for x in all_process:
            if str(x.status) == 'ESTABLISHED':
                if x.raddr.ip == switch_ip and x.raddr.port == switch_port:
                    controller_ip_port = str(x.laddr.ip) + '_' + str(x.laddr.port)
                    self.operate_zkServer(dpid, link, nodes, edges, controller_ip_port)
                    if controller_ip_port not in self.controller:
                        self.controller.append(controller_ip_port)

    def operate_zkServer(self, dpid, link, nodes, edges, controller_ip_port):
        # jude root nodes
        if not self.zks.jude_node_exists(controller_ip_port):
            self.zks.create_zk_node(controller_ip_port + '/', '')
            if len(nodes) != 0:
                self.zks.create_zk_node(controller_ip_port + '/' + 'nodes',
                                        bytes(nodes))
            if len(edges.edges) != 0:
                edgg = []
                self.zks.create_zk_node(controller_ip_port + '/' + 'edges', '')
                for node, port in nx.get_edge_attributes(edges, 'attr_dict').items():
                    n1, n2 = node
                    if port['port'] == 0:
                        edge = (n1, n2)
                    else:
                        edge = (n1, n2, {'attr_dict': port})
                    edgg.append(edge)
                self.zks.set_zk_node(controller_ip_port + '/' + 'edges', bytes(edgg))
            if len(self.port_forwarded) != 0:
                self.zks.create_zk_node(controller_ip_port + '/' + 'port_forward',
                                        bytes(self.port_forwarded))
        if self.zks.jude_node_exists(controller_ip_port):
            if self.zks.jude_node_exists(controller_ip_port + '/' + 'nodes'):
                get_nodes = self.zks.get_zk_node(controller_ip_port + '/' + 'nodes')
                if literal_eval(bytes(nodes)) != literal_eval(get_nodes[1][0]):
                    self.zks.set_zk_node(controller_ip_port + '/' + 'nodes',
                                         bytes(nodes))
            if not self.zks.jude_node_exists(controller_ip_port + '/' + 'nodes'):
                if len(nodes) != 0:
                    self.zks.create_zk_node(controller_ip_port + '/' + 'nodes',
                                            bytes(nodes))
            if self.zks.jude_node_exists(controller_ip_port + '/' + 'edges'):
                get_edges = self.zks.get_zk_node(controller_ip_port + '/' + 'edges')
                edgg = []
                for node, port in nx.get_edge_attributes(edges, 'attr_dict').items():
                    n1, n2 = node
                    if port['port'] == 0:
                        edge = (n1, n2)
                    else:
                        edge = (n1, n2, {'attr_dict': port})
                    edgg.append(edge)
                if edgg != literal_eval(get_edges[1][0]):
                    self.zks.set_zk_node(controller_ip_port + '/' + 'edges',
                                         bytes(edgg))
            if not self.zks.jude_node_exists(controller_ip_port + '/' + 'edges'):
                edgg = []
                for node, port in nx.get_edge_attributes(edges, 'attr_dict').items():
                    n1, n2 = node
                    if port['port'] == 0:
                        edge = (n1, n2)
                    else:
                        edge = (n1, n2, {'attr_dict': port})
                    edgg.append(edge)
                self.zks.create_zk_node(controller_ip_port + '/' + 'edges',
                                        bytes(edgg))
            if not self.zks.jude_node_exists(controller_ip_port + '/' + 'port_forward'):
                if len(self.port_forwarded) != 0:
                    self.zks.create_zk_node(controller_ip_port + '/' + 'port_forward',
                                            bytes(self.port_forwarded))
            if self.zks.jude_node_exists(controller_ip_port + '/' + 'port_forward'):
                if len(self.port_forwarded) != 0:
                    self.zks.set_zk_node(controller_ip_port + '/' + 'port_forward',
                                         bytes(self.port_forwarded))

    def all_topology(self, controller_info):
        all_topo = nx.DiGraph()
        # get zkServer saved controller nodes and edges
        get_root_node = self.zks.get_zk_node('/')
        if len(get_root_node) != 0:
            for controller in (get_root_node[0])[1:]:
                if self.zks.jude_node_exists(str(controller)):
                    if self.zks.jude_node_exists(str(controller) + '/' + 'nodes'):
                        get_controller_nodes = self.zks.get_zk_node(str(controller) + '/' + 'nodes')
                        for nodes in literal_eval(get_controller_nodes[1][0]):
                            all_topo.add_node(nodes)
                    if self.zks.jude_node_exists(str(controller) + '/' + 'edges'):
                        get_controller_edges = self.zks.get_zk_node(str(controller) + '/' + 'edges')
                        for edges in literal_eval(get_controller_edges[1][0]):
                            all_topo.add_edges_from([edges])

        return all_topo

    # def all_forward_port(self, dpid, network):
    #     # get zkServer saved controller nodes and edges
    #     get_root_node = self.zks.get_zk_node('/')
    #     if len(get_root_node) != 0:
    #         for controller in (get_root_node[0])[1:]:
    #             # get zkserver 'port_forward'
    #             if self.zks.jude_node_exists(str(controller) + '/' + 'port_forward'):
    #                 get_port_forward = self.zks.get_zk_node(str(controller) + '/' + 'port_forward')
    #                 for port in get_port_forward[1][:-1]:
    #                     if not self.jude_port_dict(self.all_port_forwarded, literal_eval(port)):
    #                         for k, v in literal_eval(port).items():
    #                             if k in self.all_port_forwarded and self.all_port_forwarded[k] != v:
    #                                 self.all_port_forwarded[k] = v
    #                             elif k not in self.all_port_forwarded:
    #                                 self.all_port_forwarded[k] = v
    #
    #         # print('port:',self.all_port_forwarded)
    #     for node in network.nodes:
    #         # print('node:',type(node))
    #         for k, v in network[node].items():
    #             port = v['attr_dict']['port']
    #             if len(self.all_port_forwarded) != 0:
    #                 if node in self.all_port_forwarded:
    #                     if port not in self.all_port_forwarded[node]:
    #                         if port != '3' and dpid not in [3, 6, 13, 16]:
    #                             # 需要删除正反向链路,计算最短路径时若有一条链路没删除,
    #                             # 将提示A to B 无链路(无法正确连通).
    #                             if type(node) is int:
    #                                 network.remove_edge(node, k)
    #                                 network.remove_edge(k, node)
    #
    #     return network
    #
    # def jude_port_dict(self, dict1, dict2):
    #     for i, j in dict1.items():
    #         if i in dict2.keys():
    #             if j == dict2[i]:
    #                 return True
    #
    #     return False

# def operate_zkServer(self,get_avai_port,dpid):
#     for k,v in get_avai_port[dpid].items():

# def _arp_handler(self, datapath, msg, arp_pkt):
#     '''
#     ARP_REQUEST = 1
#     ARP_REPLY = 2
#     ARP_REV_REQUEST = 3
#     ARP_REV_REPLY = 4
#     '''
#     in_port = msg.match['in_port']
#     src_ip = arp_pkt.src_ip
#     src_mac = arp_pkt.src_mac
#     # dst_ip = arp_pkt.dst_ip
#     # dst_mac = arp_pkt.dst_mac
#     # opcode = arp_pkt.opcode
#     dpid = datapath.id
#
#     if src_ip not in self.arp_table[dpid]:
#         self.arp_table[dpid][src_ip] = (src_mac, {'in_port': in_port})
#
#     print('arp', self.arp_table)

# def _icmp_handler(self, msg, icmp_pkt):
#     '''
#     ICMP_ECHO_REPLY = 0
#     ICMP_DEST_UNREACH = 3
#     ICMP_SRC_QUENCH = 4
#     ICMP_REDIRECT = 5
#     ICMP_ECHO_REQUEST = 8
#     ICMP_TIME_EXCEEDED = 11
#
#     ICMP_ECHO_REPLY_CODE = 0
#     ICMP_HOST_UNREACH_CODE = 1
#     ICMP_PORT_UNREACH_CODE = 3
#     ICMP_TTL_EXPIRED_CODE = 0
#     '''
#     type = icmp_pkt.type
#     print('type', type)
