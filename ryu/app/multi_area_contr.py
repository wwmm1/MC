#-*- conding:utf-8 -*-
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet,ethernet,ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch,get_link,get_host
import zookeeper_server
import networkx as nx
import matplotlib.pyplot as plt


class Mutlti_Area_Contr(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(Mutlti_Area_Contr,self).__init__(*args,**kwargs)
        # self.mac_to_port = {}
        self.topology_api_app = self
        self.network = nx.Graph()
        self.paths = {}


    #switch features
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_hanlder(self,ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath,0,match,actions)

    #add flow-table
    def add_flow(self,datapath, priority, match, actions, buffer_id = None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority,match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match,instructions=inst)

        datapath.send_msg(mod)

    #packet_in packet
    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        # dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        src = eth_pkt.src
        dst = eth_pkt.dst

        out_port = self.get_out_port(datapath,src,dst,in_port)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port = in_port,eth_dst = dst)
            self.add_flow(datapath,1,match,actions)

        out = parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,
                                  in_port=in_port,actions=actions,data=msg.data)

        datapath.send_msg(out)


        # msg = ev.msg
        # datapath = msg.datapath
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        # in_port = msg.match['in_port']
        #
        # dpid = datapath.id
        # #dpid:{mac:port}
        # self.mac_to_port.setdefault(dpid,{})
        #
        # pkt = packet.Packet(msg.data)
        # eth = pkt.get_protocols(ethernet.ethernet)[0]
        # #lldp packet
        # lldp_packet = ether_types.ETH_TYPE_LLDP
        #
        # dst = eth.dst  #destination mac
        # src = eth.src  #srouce mac
        #
        # self.mac_to_port[dpid][src] = in_port
        #
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        #
        # actions = [parser.OFPActionOutput(out_port)]
        #
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        #
        #     if msg.buffer_id != ofproto.OFPCML_NO_BUFFER:
        #         self.add_flow(datapath,1,match,actions,msg.buffer_id)
        #         return
        #     else:
        #         self.add_flow(datapath,1,match,actions)
        #
        # data = None
        # if msg.buffer_id == ofproto.OFPCML_NO_BUFFER:
        #     data = msg.data
        #
        # out = parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,
        #                           in_port=in_port,actions=actions,data=data)
        # datapath.send_msg(out)

    #get all switch info and all links
    # @set_ev_cls([event.EventSwitchEnter,event.EventSwitchLeave,
    #              event.EventPortAdd,event.EventPortDelete,
    #              event.EventPortModify,event.EventLinkAdd,event.EventLinkDelete],
    #             [CONFIG_DISPATCHER,MAIN_DISPATCHER])
    @set_ev_cls([event.EventSwitchEnter],[CONFIG_DISPATCHER,MAIN_DISPATCHER])
    def get_topology(self,ev):
        switch_list = get_switch(self.topology_api_app,None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)

        link_list = get_link(self.topology_api_app,None)
        links = [(link.src.dpid,link.dst.dpid,{"attr_dict":{'port':link.src.port_no}}) for link in link_list]
        self.network.add_edges_from(links)

        #dst to src links
        links = [(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}})
                    for link in link_list]
        self.network.add_edges_from(links)

        # print(dir(ev.link.dst.port_no))
        # #get switch(dpid)
        # switch_list = get_switch(self.topology_api_app,None)
        # switches = [switch.dp.id for switch in switch_list]     #switches
        # # switch = ev.switch.dp.id           #switch dpid
        # # print(ev.switch.dp.id)
        # self.network.add_nodes_from(switches)
        #
        # #get src links
        # link_list = get_link(self.topology_api_app,None)
        # # srclinks = [(link.src.dpid,link.dst.dpid,{'attr_dict':{'port':link.src.port_no,'srcmac':link.src.hw_addr}})
        # #             for link in link_list]
        # srclinks = [(link.src.dpid,link.dst.dpid,{'attr_dict':{'port':link.src.port_no}})
        #             for link in link_list]
        # # aa = [link.dst.hw_addr for link in link_list]
        # # print('srclinks:',srclinks)
        # self.network.add_edges_from(srclinks)
        #
        # #reverse links
        # dstlinks = [(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}})
        #             for link in link_list]
        # # print('dst_links:',dstlinks)
        # self.network.add_edges_from(dstlinks)
        #
        # #get host
        # hosts_list = get_host(self.topology_api_app)
        # hosts = [(host.port.dpid,host.port.port_no,{'attr_dict':{'ip':host.ipv4,'mac':host.mac}})
        #         for host in hosts_list]
        #
        # if type(ev) == event.EventSwitchLeave:
        #     print('swleave:',ev)
        # if type(ev) == event.EventLinkDelete:
        #     print('linkdel:',ev)
        # if type(ev) == event.EventLinkAdd:
        #     print('linkadd:',ev.link.dst.port_no)

        # get all switches,links,hosts
        # add_switch_inf_to_ZkServer(switches,srclinks,hosts)

    def get_out_port(self,datapath,src,dst,in_port):
        dpid = datapath.id

        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(dpid, src, attr_dict={'port': in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})

        if dst in self.network:
            if dst not in self.paths[src]:
                path = nx.shortest_path(self.network, src, dst)     #algorithm shorst path
                self.paths[src][dst] = path

            path = self.paths[src][dst]
            # p1 = nx.all_shortest_paths(self.network,source='00:00:00:00:00:01',target='00:00:00:00:00:03')
            next_hop = path[path.index(dpid) + 1]
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
            # print([p for p in p1])
            print(dpid)
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        return out_port


# add switch information to zk_server
def add_switch_inf_to_ZkServer(switches,srclinks,hosts=None):
    # switches = '/' + str(switches)
    # linkes = str(srclinks)
    #get zk node,judge node whether is null
    zk = zookeeper_server.Zookeeper_Server('127.0.0.1','4181')
    # print('switch:',switches)     #('switch:', [1, 2, 3])
    # print('srclinks:',srclinks)   #('srclinks:', [(2, 3, {'attr_dict': {'port': 3, 'srcmac': '72:f4:db:b7:8f:21'}}),
                                  # (2, 1, {'attr_dict': {'port': 2, 'srcmac': '22:56:29:00:71:a0'}}),
                                  # (3, 2, {'attr_dict': {'port': 2, 'srcmac': '36:fa:6e:fe:7f:20'}}),
                                  # (1, 2, {'attr_dict': {'port': 2, 'srcmac': 'f6:3d:a0:bf:ed:ef'}})])

    # print('hosts:',hosts)        #('hosts:', [(2, 1, {'attr_dict': {'ip': [], 'mac': '96:e9:18:fc:8c:14'}}),
                                 # (3, 1, {'attr_dict': {'ip': [], 'mac': '0a:c0:04:59:2f:b1'}}),
                                 # (1, 1, {'attr_dict': {'ip': [], 'mac': '16:31:3d:97:c5:75'}})])

    #check node and values and ,if node or values or host is nothing, add them
    if zk.jude_node_exists('/controller'):
        for switcha in switches:
            #add links between switch and switch
            for links in srclinks:
                if zk.jude_node_exists('/controller' + '/' + str(switcha)):
                    get_node = zk.get_zk_node('/controller' + '/' + str(switcha))[0]
                    if switcha == links[0]:
                        node_value = {}
                        for node in get_node:
                            if zk.jude_node_exists('/controller' + '/' + str(switcha) + '/' + node):
                                get_value = zk.get_zk_node('/controller' + '/' + str(switcha) + '/' + node)[1][0]
                                node_value[str(node)] = eval(get_value)
                        if links not in node_value.values():
                            zk.create_zk_node('/controller' + '/' +str(switcha) + '/' + 'link',links)
                else:
                    if switcha == links[0]:
                        zk.create_zk_node('/controller' + '/' + str(switcha) + '/' + 'link', links)
            #add links between switch and host
            for host in hosts:
                if zk.jude_node_exists('/controller' + '/' + str(switcha)):
                    get_node = zk.get_zk_node('/controller' + '/' + str(switcha))[0]
                    if switcha == host[0]:
                        host_node_value = {}
                        for node in get_node:
                            if zk.jude_node_exists('/controller' + '/' + str(switcha) + '/' + node):
                                get_value = zk.get_zk_node('/controller' + '/' + str(switcha) + '/' + node)[1][0]
                                host_node_value[str(node)] = eval(get_value)
                        if host not in host_node_value.values():
                            zk.create_zk_node('/controller' + '/' + str(switcha) + '/' + 'host', host)
                else:
                    if switcha == host[0]:
                        zk.create_zk_node('/controller' + '/' + str(switcha) + '/' + 'host', host)

