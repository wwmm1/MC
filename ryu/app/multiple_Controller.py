#-*- coding:utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import xml.dom.minidom
import psutil
import os


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ping_thread = hub.spawn(self.send_heartbeat_packet)
        self.cIP_address = []
        self.dp = ''
        self.go_role = ''

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.send_role_request(datapath)
        self.dp = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
    def role_reply_handler(self,ev):
        msg = ev.msg
        dpp = msg.datapath
        ofp = dpp.ofproto

        if msg.role == ofp.OFPCR_ROLE_NOCHANGE:
            role = 'NOCHANGE'
        elif msg.role == ofp.OFPCR_ROLE_EQUAL:
            role = 'EQUAL'
        elif msg.role == ofp.OFPCR_ROLE_MASTER:
            role = 'MASTER'
        elif msg.role == ofp.OFPCR_ROLE_SLAVE:
            role = 'SLAVE'
        else:
            role = 'unknown'

        self.go_role = role

    #比较本机启动的控制器是主控制器还是从控制器
    def judge_controller_role(self):
        #本机IP地址，转换为int类型
        localIP = get_ip_address('eno1')
        lIP = localIP.split('.')
        localIPAddress = int(lIP[0]) + int(lIP[1]) + \
                         int(lIP[2]) + int(lIP[3])

        controllerIP = readControllerXMLNode()
        if localIP in controllerIP:
            contrIPList = []
            #通过相加来判断IP地址是否为最大
            for cIP in controllerIP:
                ip = int(cIP.split('.')[0])+int(cIP.split('.')[1])+\
                     int(cIP.split('.')[2])+int(cIP.split('.')[3])
                contrIPList.append(ip)
            cIPint = contrIPList.index(max(contrIPList))
            print('cIPint:',cIPint)
            self.cIP_address.append(controllerIP[cIPint])    #最大的IP地址（主控制器的IP地址，字符串）
            if max(contrIPList) == localIPAddress:
                return True
            else:
                return False

    #下发控制器role到ovs,IP地址大的将成为master,如果IP地址相等，则报错
    def send_role_request(self,datapath):
        if self.judge_controller_role():
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPRoleRequest(datapath,ofp.OFPCR_ROLE_MASTER,0)
            datapath.send_msg(req)
        else:
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            req = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_SLAVE, 0)
            datapath.send_msg(req)

    # 从控制器每隔10s主动向主控制器发送ping消息，检测主控制器是否在线，
    # 若主控制器不在线（宕机等原因），则从控制根据IP地址（IP地址的大小），产生新的主控制器
    def send_heartbeat_packet(self):
        while True:
            if self.dp:
                print('dp:', self.dp)
                if not self.judge_controller_role():
                    con_online = []
                    #IP小的控制器，检测地址比它大的IP
                    for ip in compare_IP('eno1'):
                        ping_MCon = os.system('ping -c 1 -w 1 %s' % ip)  # ping主控制器，判断主控制器是否在线
                        if ping_MCon == 0:
                            con_online.append('T')    #控制器在线
                        else:
                            con_online.append('F')    #控制器不在线

                    #读取本地IP，防止类似‘127.0.0.1’不再xml的地址成为主控制器
                    lip = get_ip_address('eno1')

                    #主控制器不在线时，重新选举IP大的作为主控制器，若主控制器上线，重新将新选举的主控制器设置为从控制器
                    if 'T' not in con_online and self.go_role != 'MASTER' and lip in readControllerXMLNode():
                        ofp = self.dp.ofproto
                        ofp_parser = self.dp.ofproto_parser

                        req = ofp_parser.OFPRoleRequest(self.dp, ofp.OFPCR_ROLE_MASTER, 0)
                        self.dp.send_msg(req)
                    elif 'T' in con_online and 'F' in con_online and self.go_role != 'SLAVE' and lip in readControllerXMLNode():
                        ofp = self.dp.ofproto
                        ofp_parser = self.dp.ofproto_parser

                        req = ofp_parser.OFPRoleRequest(self.dp, ofp.OFPCR_ROLE_SLAVE, 0)
                        self.dp.send_msg(req)

            hub.sleep(10)


    def receive_heartbeat_packet(self):
        pass

#从controllerNode读取控制器IP地址
def readControllerXMLNode():
    contrIP = []
    dom = xml.dom.minidom.parse('controllerNode.xml')
    root = dom.documentElement
    controllerIP = root.getElementsByTagName('controller-ip')

    for ip in controllerIP:
        contrIP.append(ip.childNodes[0].nodeValue)

    # return controller IP : list
    return contrIP

#获得本机IP地址
def get_ip_address(netCard):
    localIP = ''
    dic = psutil.net_if_addrs()
    for snic in dic[netCard]:
        #判断是否为IPv4地址（2为IPv4,10为IPv6地址.10为packet包）
        if not snic.family == 2:
            continue
        localIP = snic.address

    return localIP

#获得列表中比本地IP大的地址
def compare_IP(netCard):
    #获取本地IP地址
    localIP = get_ip_address(netCard)
    lip = localIP.split('.')
    localIPAddress = int(lip[0]) + int(lip[1]) + \
                     int(lip[2]) + int(lip[3])

    #比较本地IP地址和列表的地址，如果比本地IP地址大，则加入xmlControllerIP列表
    xmlControllerIP = []
    for ip in readControllerXMLNode():
        ipp = ip.split('.')
        ipp_ip = int(ipp[0]) + int(ipp[1]) + \
                 int(ipp[2]) + int(ipp[3])
        if ipp_ip > localIPAddress:
            xmlControllerIP.append(ip)

    return xmlControllerIP




