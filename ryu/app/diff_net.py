from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp, icmp, ipv4
import xml.dom.minidom


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}
        self.dpid_port_mac = {}  # dpid:{port:mac}
        self.dpid_port_ip = {}  # dpid:{port:ip}
        self.dpid_port_mac_ip = {}  # dpid:{port:{mac:ip}}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        arp_pkt = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if arp_pkt != None:
            self.arp_handler(datapath, msg)
            # print('1')
            print('msg', self.port_dpid)
            # print('pkt',pkt)
        if icmp_pkt != None:
            self.icmp_handler(datapath, msg)
            print('2')

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    def arp_handler(self, datapath, msg):
        pass

    def icmp_handler(self, datapath, msg):
        pass

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        '''
        self.port_dpid  => {dpid:{port:port_mac_address}}
        example : {1: {1: 'ce:ce:37:00:56:d5', 2: '16:ae:7d:82:a2:44'}}
        '''
        msg = ev.msg
        port_desc = msg.desc
        dpid = msg.datapath.id
        self.dpid_port_mac.setdefault(dpid, {})

        port_no = port_desc.port_no
        port_hw_addr = port_desc.hw_addr

        self.dpid_port_mac[dpid][port_no] = port_hw_addr

        self.get_switch_port_ip(self.dpid_port_mac)

        # self.arp_handler(msg.datapath,msg)

        # print(self.port_dpid)

    def get_switch_port_ip(self, dpid_port_mac):
        '''
        ('port_id', u'1')
        ('port_ip', u'192.168.6.1')
        ('s_id', u'6')
        ({'1': {'1': '192.168.1.1'}, '3': {'1': '192.168.3.1'}, '2': {'1': '192.168.2.1'},
        '5': {'1': '192.168.5.1'}, '4': {'1': '192.168.4.1'}, '6': {'1': '192.168.6.1'}})
        '''
        # print('d_p_m', dpid_port_mac)
        dom = xml.dom.minidom.parse('ip_router.xml')
        root = dom.documentElement

        switchs = root.getElementsByTagName('switch')
        for switch in switchs:
            switch_id = str(switch.getAttribute('id'))  # switch_id convert string
            if switch_id not in self.dpid_port_ip:
                self.dpid_port_ip.setdefault(switch_id, {})
            switch_port = switch.getElementsByTagName('port')
            for port in switch_port:
                port_id = str(port.getAttribute('id'))  # port_id convert string
                port_ip = str(port.childNodes[0].data)  # port_ip convert string
                if port_id not in self.dpid_port_ip[switch_id]:
                    self.dpid_port_ip[switch_id][port_id] = port_ip

        if self.dpid_port_ip:
            # print('d_p_i', self.dpid_port_ip)
            for dpi, po_id in self.dpid_port_ip.items():  # get key,values --> key = dpid, values = {'port':'ip'}
                dp_id = int(dpi)
                # print('dp_id', dp_id)
                # print('po_id', po_id)
                self.dpid_port_mac_ip.setdefault(dp_id, {})
                if dpid_port_mac.get(dp_id) is not None:
                    for k, v in po_id.items():  # k --> port_id, v --> port_ip
                        p_id = int(k)
                        p_ip = v
                        # print('p_id', p_id)
                        # print('p_ip', p_ip)
                        # print('dp:', dpid_port_mac.get(int(dp_id)))
                        if p_id not in self.dpid_port_mac_ip[dp_id]:
                            for p_k, p_m in dpid_port_mac.get(dp_id).items():  # p_k --> port_id, p_m --> port_mac
                                # print('p_k', p_k)
                                # print('p_m', p_m)
                                if int(p_id) == p_k:
                                    self.dpid_port_mac_ip[dp_id][p_id] = (p_m, p_ip)

        # print('dpmi',self.dpid_port_mac_ip)
