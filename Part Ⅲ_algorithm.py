from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu import utils


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]  # OFP_VERSIONS is specified as OpenFlow1.3.

    def __init__(self, *args, **kwargs):
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.FLAGS = True

    @set_ev_cls(  # Handling error reporting events
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    # This function is used to handle the EventOFPErrorMsg event, which is triggered when the switch is in the following states
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPStateChange,  # Adding and removing switches when handling switch state changes
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:  #Join if not in
            if not datapath.id in self.datapaths:  
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:  #Delete if you leave
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    
    # configure the switch when it is connected to the switch (here mainly the prescribed flow table is issued)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id # ID of the connected openflow switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, #Sending port is controller     
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, hard_timeout, priority, match, actions): 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
                                             actions)]
        # The Controller (Ryu) transmits the OFPFlowMod to the Switch, and when the Switch receives this message, it adds the corresponding rule to the
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst) 
        datapath.send_msg(mod) 

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data): # buffer_id Specify the buffer corresponding to the packet on the switch
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port)) # If the destination port exists, forward it out of the destination port

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER: # If no buffer is used, specify as OFP_NO_BUFFER
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,        # If the flow table records an output port, output from that port
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def send_packet_flood(self, msg):
        datapath = msg.datapath           # Flooding to all ports if no information is recorded in the flow table
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst) 
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,  
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]  
            self.add_flow(datapath, 0, 1, match, actions) 
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.send_packet_flood(msg) 

    def mac_learning(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        if src_mac in self.mac_to_port[dpid]:   # mac_to_port:{'dpid' : {'src_mac' : 'in_port'}}
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            self.mac_to_port[dpid][src_mac] = in_port  
            return True

    def send_group_mod(self, datapath,):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port_1 = 3
        queue_1 = ofp_parser.OFPActionSetQueue(0)
        actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]

        port_2 = 2
        queue_2 = ofp_parser.OFPActionSetQueue(0)
        actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]

        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY  # OFPP_ANY = 0xffffffff  Not associated with a physical port.
        watch_group = ofproto_v1_3.OFPQ_ALL # OFPP_ALL = 0xfffffffc  All physical ports except input port.

        buckets = [
            ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
            ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        group_id = 50
        req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD, 
                                     ofproto.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0] 
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6)
            self.add_flow(datapath, 0, 1, match, actions)
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return

            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            out_port = None
            if eth.dst in self.mac_to_port[dpid]:
                if dpid == 1 and in_port == 1:
                    if self.FLAGS is True:
                        self.send_group_mod(datapath)
                        self.logger.info("send_group_mod")
                        self.FLAGS = False

                    actions = [parser.OFPActionGroup(group_id=50)]
                    match = parser.OFPMatch(in_port=in_port,
                                            eth_type=eth.ethertype,
                                            ipv4_src=ip_pkt.src)
                    self.add_flow(datapath, 0, 3, match, actions)
                    # asign output at 2
                    self.send_packet_out(datapath, msg.buffer_id,
                                         in_port, 2, msg.data)
                else:
                    #Normal flows
                    out_port = self.mac_to_port[dpid][eth.dst]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                                            eth_type=eth.ethertype)
                    self.add_flow(datapath, 0, 1, match, actions)
                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port, msg.data)
            else:
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    self.send_packet_flood(msg)