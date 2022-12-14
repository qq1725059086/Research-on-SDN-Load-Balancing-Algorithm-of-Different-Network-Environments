from ryu.base import app_manager 
from ryu.controller import ofp_event 
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3 
from ryu.topology.switches import LLDPPacket
from ryu.base.app_manager import lookup_service_brick
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet 
from ryu.topology.api import get_switch, get_link, get_host 
from ryu.topology import event, switches
import time
import networkx as nx 



class LoadBalancetool(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancetool, self).__init__(*args, *kwargs)
        self.name = 'LoadBalance'
        self.switches = lookup_service_brick('switches')

        self.G = nx.DiGraph()
        self.topology_api_app = self 

        self.dpidSwitch = {}
        self.echoDelay = {}
        self.lldpDelay = {}
        self.link_Weight = {}
        self.link_length = {}
        self.links_src_dst = []
        self.id_port = {}

        self.detector_thread = hub.spawn(self.detector)

    
    
    def detector(self):
        while True:
            self.send_echo_request()  
            self.link_Weight()  
            self.update_topo() 
            hub.sleep(3) 


    def add_flow(self, datapath, priority, match, actions):
        ofp = datapath.ofproto 
        ofp_parser = datapath.ofproto_parser 
        command = ofp.OFPFC_ADD
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        req = ofp_parser.OFPFlowMod(datapath=datapath, command=command,
                                    priority=priority, match=match, instructions=inst)
        datapath.send_msg(req) 


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg  
        datapath = msg.datapath  
        ofp = datapath.ofproto  
        ofp_parser = datapath.ofproto_parser 

        match = ofp_parser.OFPMatch()  
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(datapath=datapath, priority=0, match=match, actions=actions)


    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER]) 
    # This function is used to handle the EventOFPStateChange event, which is triggered when the switch is connected or disconnected

    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:  
            if not datapath.id in self.dpidSwitch:
                self.dpidSwitch[datapath.id] = datapath  
        elif ev.state == DEAD_DISPATCHER:  
            if datapath.id in self.dpidSwitch:
                del self.dpidSwitch[datapath.id]

    events = [event.EventSwitchEnter, event.EventSwitchLeave,   
              event.EventSwitchReconnected,                     
              event.EventPortAdd, event.EventPortDelete,
              event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]


    @set_ev_cls(events)
    def get_topo(self, ev):
        switch_list = get_switch(self.topology_api_app)
        topo_switches = []

        for switch in switch_list:
            topo_switches.append(switch.dp.id)
        self.G.add_nodes_from(topo_switches)

        link_list = get_link(self.topology_api_app)
        self.links_src_dst = []  

        for link in link_list:     
            self.links_src_dst.append([link.src.dpid, link.dst.dpid, 0]) 
        self.G.add_weighted_edges_from(self.links_src_dst)  

        for link in link_list:
            self.links_src_dst.append([link.dst.dpid, link.src.dpid, 0])
        self.G.add_weighted_edges_from(self.links_src_dst)

        
        
    def send_echo_request(self):
        for datapath in self.dpidSwitch.values():
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath, data=bytes("%.12f" % time.time(), encoding="utf8")) 

            datapath.send_msg(echo_req)
            hub.sleep(0.5)

    

    @set_ev_cls(ofp_event.EventOFPEchoReply, [MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER])
    def echo_reply_handler(self, ev):
        now_timestamp = time.time()
        try:
            echo_delay = now_timestamp - eval(ev.msg.data)
            self.echoDelay[ev.msg.datapath.id] = echo_delay
        except Exception as error:
            return


    def _save_delay_data(self, src, dst, src_port, lldp_dealy, link_length):
        key = "%s-%s-%s" % (src, src_port, dst)
        src_dst = "%s-%s" % (src, dst)
        self.id_port[src_dst] = src_port     #id_port : 'src-dst':src_port
        self.lldpDelay[key] = lldp_dealy     #lldpDelay : 'src-src_port-dst': lldp_dealy
        self.link_length[key] = link_length  #link_length : 'src-src_port-dst': link_length
    

    def link_Weight(self):
        for key in self.lldpDelay:
            list = key.split('-')  
            t1 = 0
            t2 = 0
            for key_s in self.echoDelay:   
                if key_s == int(list[0]):  
                    t1 = self.echoDelay[key_s] 
                if key_s == int(list[2]):  
                    t2 = self.echoDelay[key_s] 
            delay = self.lldpDelay[key] - (t1 + t2) / 2
            if delay>=0 | delay<=1:
                delay = self.lldpDelay[key] - (t1 + t2) / 2     
            else:
                continue
            try:
                for edge in self.link_length:
                #list2 = edge.split('-')
                #if list[0]==list2[0] && list[1]==list2[1] && list[2]==list2[2]:
                    if key==edge:
                        self.link_Weight[key] = (eval(int(self.link_length[edge]) / 10000)) + int(delay)
                    else???
                        continue
            except Exception as error:
                self.link_Weight[key] =  int(delay)
    
    def update_topo(self):
        for key in self.link_Weight: 
            list = key.split('-')  
            l = (int(list[0]), int(list[2])) 
            for i in self.links_src_dst: 
                if l == (i[0], i[1]):
                    i[2] = self.link_Weight[key]

        self.G.add_weighted_edges_from(self.links_src_dst)  

    
    def get_out_port(self, datapath, src, dst, in_port):
        global out_port
        dpid = datapath.id

        if src not in self.G:
            self.G.add_node(src)
            self.G.add_weighted_edges_from([[dpid, src, 0]])
            self.G.add_weighted_edges_from([[src, dpid, 0]])
            src_dst = "%s-%s" % (dpid, src)  
            self.id_port[src_dst] = in_port  

        
        if dst in self.G:
            path = nx.shortest_path(self.G, src, dst, weight='weight')
            next_hop = path[path.index(dpid) + 1] 

            for key in self.id_port: 
                match_key = "%s-%s" % (dpid, next_hop)
                if key == match_key:
                    out_port = self.id_port[key]

            print("--------------------------------------------------------------")
            print("The optimal path to choose is:")
            print(path)
            print("--------------------------------------------------------------")

        else:
            out_port = datapath.ofproto.OFPP_FLOOD   
        return out_port
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst 
        src = eth.src 

        try:  
            src_dpid, src_outport = LLDPPacket.lldp_parse(msg.data) 
            dst_dpid = msg.datapath.id  
            
            if self.switches is None:
                self.switches = lookup_service_brick("switches")  

            for port in self.switches.ports.keys():  
                if src_dpid == port.dpid and src_outport == port.port_no: 
                    port_data = self.switches.ports[port]  
                    timestamp = port_data.timestamp
                    if timestamp:
                        delay = time.time - timestamp
                        try:
                            for i in nx.all_simple_paths(self.G, source=src, target=dst):
                                for node1 in i:
                                    for node2 in i:
                                        if i[node1]==i[node2]:
                                            continue
                                        else:
                                            if i[1]==dst_dpid: 
                                                length=len(i)
                                            else:
                                                continue
                        except Exception as error:
                            length=0
                        
                        self._save_delay_data(src=src_dpid, dst=dst_dpid, src_port=src_outport, lldp_dealy=delay, link_length=length)
        except Exception as error:  
            out_port = self.get_out_port(datapath, src, dst, in_port) 
            actions = [ofp_parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data
            out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)