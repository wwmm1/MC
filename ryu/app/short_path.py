from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER,MAIN_DISPATCHER
from ryu.lib.packet import packet,ethernet
from ryu.topology import event
from ryu.topology.api import get_switch,get_link
import networkx as nx

class myShortForwarding(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(myShortForwarding,self).__init__(*args,**kwargs)

        self.network = nx.DiGraph()
        self.paths = {}
        self.topology_api_app = self


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

        out_port = self.get_out_port(datapath,eth_src,eth_dst,in_port)

        actions = [ofp_parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)
            self.add_flow(datapath,1,match,actions)

        out = ofp_parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id,
                                    in_port=in_port,actions=actions,data=msg.data)

        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])
    def get_topology(self,ev):
        switch_list = get_switch(self.topology_api_app,None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)

        link_list = get_link(self.topology_api_app,None)
        links = [(link.src.dpid,link.dst.dpid,{"attr_dict":{'port':link.dst.port_no}}) for link in link_list]
        self.network.add_edges_from(links)

        links = [(link.dst.dpid,link.src.dpid,{'attr_dict':{'port':link.dst.port_no}})
                 for link in link_list]
        self.network.add_edges_from(links)


    def get_out_port(self,datapath,src,dst,in_port):
        dpid = datapath.id

        if src not in self.network:
            self.network.add_node(src)
            self.network.add_edge(dpid,src,attr_dict={'port':in_port})
            self.network.add_edge(src,dpid)
            self.paths.setdefault(src,{})

        if dst in self.network:
            if dst not in self.paths[src]:
                path = nx.shortest_path(self.network,src,dst)
                self.paths[src][dst] = path

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid)+1]
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
            print(path)
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
        return out_port