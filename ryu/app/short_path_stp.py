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
        # self.port_block = []
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
        # arp_pkt = pkt.get_protocol(arp.arp)
        # ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        # icmp_pkt = pkt.get_protocol(icmp.icmp)

        # self.arp_table.setdefault(dpid, {})

        # if arp_pkt != None:
        #     self._arp_handler(datapath, msg, arp_pkt)
        # if icmp_pkt != None:
        #     self._icmp_handler(msg, icmp_pkt)

        # ignore lldp packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

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

        # if dpid not in self.controller:
        #     self.controller.append(dpid)

        # self.send_role_request(datapath)

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
        dpid = datapath.id
        # 返回删除了阻断端口链路的network

        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(dpid, src, attr_dict={'port': in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})

        get_avai_port = self.get_avai_port(dpid, self.network)

        if datapath.address not in self.sw_info:
            self.sw_info.append(datapath.address)
            self.get_process(dpid, get_avai_port[dpid], get_avai_port.nodes,
                             get_avai_port.edges, datapath.address)

        self.all_topology(self.controller)

        if dst in get_avai_port:
            if dst not in self.paths[src]:
                path = nx.shortest_path(get_avai_port, src, dst)
                self.paths[src][dst] = path

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid) + 1]
            out_port = get_avai_port[dpid][next_hop]['attr_dict']['port']
            # print('path:',path)
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        # print("out_port:",out_port)
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
                    network.remove_edge(dpid, k)
                    network.remove_edge(k, dpid)

        return network

    def write_to_txt(self, content):
        with open('aa.txt', 'a') as f:
            f.write(content)
            f.write('\n')

    def get_process(self, dpid, link, nodes, edges, switch_address_port):
        switch_ip, switch_port = switch_address_port  # get switch ip and port
        # print('switch:',switch_ip)
        # print('port:',switch_port)
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
        # switch_ip, switch_port = switch_address_port  # get switch ip and port
        # jude root nodes
        if not self.zks.jude_node_exists(controller_ip_port):
            self.zks.create_zk_node(controller_ip_port + '/', '')
            self.zks.create_zk_node(controller_ip_port + '/' + str(dpid), '')
            if len(link) != 0:
                for i, l in enumerate(link.items()):
                    self.zks.create_zk_node(controller_ip_port + '/' + str(dpid) + '/' + str(i), l)
            if len(nodes) != 0:
                self.zks.create_zk_node(controller_ip_port + '/' + 'nodes', nodes)
            if len(edges) != 0:
                self.zks.create_zk_node(controller_ip_port + '/' + 'edges', edges)
        elif self.zks.jude_node_exists(controller_ip_port):
            if not self.zks.jude_node_exists(controller_ip_port + '/' + str(dpid)):
                self.zks.create_zk_node(controller_ip_port + '/' + str(dpid), '')
                if len(link) != 0:
                    for i, l in enumerate(link.items()):
                        self.zks.create_zk_node(controller_ip_port + '/' + str(dpid) + '/' + str(i), l)
            else:
                if len(link) != 0:
                    for i, l in enumerate(link.items()):
                        self.zks.set_zk_node(controller_ip_port + '/' + str(dpid) + '/' + str(i), l)
            if not self.zks.jude_node_exists(controller_ip_port + '/' + 'nodes') and len(nodes) != 0:
                self.zks.create_zk_node(controller_ip_port + '/' + 'nodes', bytes(nodes))
            elif len(nodes) != 0:
                self.zks.set_zk_node(controller_ip_port + '/' + 'nodes', bytes(nodes))
            if not self.zks.jude_node_exists(controller_ip_port + '/' + 'edges') and len(edges) != 0:
                self.zks.create_zk_node(controller_ip_port + '/' + 'edges', bytes(edges))
            elif len(edges) != 0:
                self.zks.set_zk_node(controller_ip_port + '/' + 'edges', bytes(edges))

    def all_topology(self, controller_info):
        # get zkServer saved controller nodes and edges
        all_topo = nx.DiGraph()
        for controller in controller_info:
            if self.zks.jude_node_exists(controller):
                get_controller_nodes = self.zks.get_zk_node(controller + '/' + 'nodes')
                get_controller_edges = self.zks.get_zk_node(controller + '/' + 'edges')
                # all_topo.add_nodes_from(list(get_controller_nodes[1])[0])
                # all_topo.add_edges_from(list(get_controller_edges[1])[0])
                print(list(get_controller_edges[1])[0])
                # print(list(get_controller_nodes[1])[0])

        # print('all_topo:', all_topo)

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
