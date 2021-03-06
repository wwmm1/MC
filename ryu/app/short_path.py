from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.lib.packet import packet,ethernet,ether_types
from ryu.topology import event
from ryu.topology.api import get_switch,get_link

from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib

import networkx as nx
import zookeeper_server

class myShortForwarding(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib':stplib.Stp}

    def __init__(self,*args,**kwargs):
        super(myShortForwarding,self).__init__(*args,**kwargs)

        self.network = nx.DiGraph()
        self.paths = {}
        self.topology_api_app = self

        self.mac_to_port = {}
        self.stp = kwargs['stplib']

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_feature_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath,0,match,actions)

    def add_flow(self,datapath,priority,match,actions):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        mod = ofp_parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst

        # if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
        #     return

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            # out_port = self.get_out_port(datapath,eth_src,eth_dst,in_port)
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)
            self.add_flow(datapath,1,match,actions)

        out = ofp_parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,
                                    in_port=in_port,actions=actions,data=msg.data)

        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange,MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange,MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])
    def get_topology(self,ev):
        switch_list = get_switch(self.topology_api_app,None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)

        link_list = get_link(self.topology_api_app,None)
        links = [(link.src.dpid,link.dst.dpid,{'attr_dict':{'port':link.src.port_no}})
                 for link in link_list]
        self.network.add_edges_from(links)

        links = [(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}})
                 for link in link_list]
        self.network.add_edges_from(links)

        # print(links)

    def get_out_port(self,datapath,src,dst,in_port):
        dpid = datapath.id

        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(dpid,src,attr_dict={'port':in_port})
            self.network.add_edge(src,dpid)
            self.paths.setdefault(src,{})

        print(self.network[1][3]['attr_dict']['port'])

        if dst in self.network:
            if dst not in self.paths[src]:
                path = nx.shortest_path(self.network,src,dst)
                self.paths[src][dst] = path
                # print(path)

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid)+1]
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        return out_port

# add switch information to zk_server
# def add_switch_inf_to_ZkServer(switches,srclinks,hosts=None):
#     zk = zookeeper_server.Zookeeper_Server('127.0.0.1','4181')
#
#     #check node and values and ,if node or values or host is nothing, add them
#     if zk.jude_node_exists('/controller'):
#         for switcha in switches:
#             #add links between switch and switch
#             for links in srclinks:
#                 if zk.jude_node_exists('/controller' + '/' + str(switcha)):
#                     get_node = zk.get_zk_node('/controller' + '/' + str(switcha))[0]
#                     if switcha == links[0]:
#                         node_value = {}
#                         for node in get_node:
#                             if zk.jude_node_exists('/controller' + '/' + str(switcha) + '/' + node):
#                                 get_value = zk.get_zk_node('/controller' + '/' + str(switcha) + '/' + node)[1][0]
#                                 node_value[str(node)] = eval(get_value)
#                         if links not in node_value.values():
#                             zk.create_zk_node('/controller' + '/' +str(switcha) + '/' + 'link',links)
#                 else:
#                     if switcha == links[0]:
#                         zk.create_zk_node('/controller' + '/' + str(switcha) + '/' + 'link', links)
#             #add links between switch and host
#             for host in hosts:
#                 if zk.jude_node_exists('/controller' + '/' + str(switcha)):
#                     get_node = zk.get_zk_node('/controller' + '/' + str(switcha))[0]
#                     if switcha == host[0]:
#                         host_node_value = {}
#                         for node in get_node:
#                             if zk.jude_node_exists('/controller' + '/' + str(switcha) + '/' + node):
#                                 get_value = zk.get_zk_node('/controller' + '/' + str(switcha) + '/' + node)[1][0]
#                                 host_node_value[str(node)] = eval(get_value)
#                         if host not in host_node_value.values():
#                             zk.create_zk_node('/controller' + '/' + str(switcha) + '/' + 'host', host)
#                 else:
#                     if switcha == host[0]:
#                         zk.create_zk_node('/controller' + '/' + str(switcha) + '/' + 'host', host)