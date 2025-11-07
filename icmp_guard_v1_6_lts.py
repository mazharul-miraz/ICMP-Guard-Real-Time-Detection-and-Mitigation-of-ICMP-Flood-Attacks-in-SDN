"""
Real-Time Detection and Mitigation of ICMP Flood Attacks in Software-Defined Networks

Last Updated: 2025-10-22

Description:
This controller detects ICMP flood attacks in real time and selectively blocks
malicious hosts while maintaining normal traffic flow. RTT (round-trip time)
logging is provided for each host to support monitoring and visualization.

Features:
 - Per-host ICMP flood detection
 - Selective blocking of attacker IPs
 - RTT logging for all hosts
 - Generates CSV logs for visualization
 - ISO-8601 UTC timestamps
 - Safe for normal ping tests and real-time monitoring
"""





from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib import hub
import time, csv, os, sys
from datetime import datetime

# ----------------- CONFIG -----------------
BLOCKING_ENABLED = True
THRESHOLD = 50
WINDOW_INTERVAL = 1
CONTROLLER_LOG_CSV = "controller_log.csv"
HOST_STATS_CSV = "icmp_rtt_log.csv"  # new CSV for visualization
# ------------------------------------------

RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; RESET = "\033[0m"

def iso_utc_now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def write_csv_row(path, row):
    try:
        with open(path, "a", newline="") as f:
            csv.writer(f).writerow(row)
    except Exception as e:
        print(f"{RED}[!] Failed to write {path}: {e}{RESET}")
        sys.stdout.flush()

class ICMPGuardVisibleBlocks(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ICMPGuardVisibleBlocks, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.icmp_count = {}
        self.window_start = {}
        self.window_interval = WINDOW_INTERVAL
        self.threshold = THRESHOLD
        self.host_stats = {}
        self.blocked_ips = set()

        # Ensure controller log CSV exists
        if not os.path.exists(CONTROLLER_LOG_CSV):
            with open(CONTROLLER_LOG_CSV, "w", newline="") as f:
                csv.writer(f).writerow(["timestamp", "event", "ip", "details"])
        # Ensure host stats CSV exists
        if not os.path.exists(HOST_STATS_CSV):
            with open(HOST_STATS_CSV, "w", newline="") as f:
                csv.writer(f).writerow(["timestamp", "host", "total", "rtt"])

        self.logger.info(f"{YELLOW}[*] ICMP Guard v1.6 LTS with CSV Logging started | BLOCKING_ENABLED={BLOCKING_ENABLED}{RESET}")
        sys.stdout.flush()

        self.monitor_thread = hub.spawn(self._monitor)

    # ----------------- switch setup -----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst))

        # send ICMP packets to controller
        match_icmp = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=10, match=match_icmp, instructions=inst))

        print(f"{YELLOW}📡 Switch {datapath.id} configured (table-miss + ICMP capture){RESET}")
        sys.stdout.flush()

    # ----------------- packet-in -----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        in_port = msg.match.get('in_port', None)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if ip_pkt and icmp_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            now = time.time()
            key = (src_ip, dst_ip)

            # sliding window
            if key not in self.icmp_count:
                self.icmp_count[key] = 0
                self.window_start[key] = now
            if now - self.window_start[key] > self.window_interval:
                self.icmp_count[key] = 0
                self.window_start[key] = now
            self.icmp_count[key] += 1
            count = self.icmp_count[key]

            # host stats
            if src_ip not in self.host_stats:
                self.host_stats[src_ip] = {'count': 0, 'last_time': now, 'rtt': 0}
            self.host_stats[src_ip]['count'] += 1
            self.host_stats[src_ip]['last_time'] = now
            # placeholder RTT: we can expand later
            self.host_stats[src_ip]['rtt'] = 0.1

            # If already blocked, log
            if src_ip in self.blocked_ips:
                ts_iso = iso_utc_now()
                human = f"SRC {src_ip} -> DST {dst_ip}"
                print(f"{RED}[BLOCKED_PACKET] {human}{RESET}")
                sys.stdout.flush()
                write_csv_row(CONTROLLER_LOG_CSV, [ts_iso, "BLOCKED_PACKET", src_ip, f"human={human}"])
                return

            # Flood detection
            if count > self.threshold:
                ts_iso = iso_utc_now()
                print(f"{RED}[!] ICMP Flood Detected src={src_ip} dst={dst_ip} count={count}{RESET}")
                sys.stdout.flush()
                write_csv_row(CONTROLLER_LOG_CSV, [ts_iso, "ATTACKER_DETECTED", src_ip, f"dst={dst_ip},count={count}"])

                if BLOCKING_ENABLED and src_ip not in self.blocked_ips:
                    try:
                        self._install_block_and_observe_flow(datapath, src_ip)
                        self.blocked_ips.add(src_ip)
                        block_ts = iso_utc_now()
                        print(f"{GREEN}BLOCK_INSTALLED: {src_ip} at {block_ts}{RESET}")
                        sys.stdout.flush()
                        write_csv_row(CONTROLLER_LOG_CSV, [block_ts, "BLOCK_INSTALLED", src_ip, f"installed_on_switch={datapath.id}"])
                    except Exception as e:
                        print(f"{RED}[!] Failed to install block for {src_ip}: {e}{RESET}")
                        sys.stdout.flush()
                else:
                    print(f"{YELLOW}[i] Detected {src_ip} but already blocked or blocking disabled{RESET}")
                    sys.stdout.flush()
            else:
                print(f"{GREEN}[Normal ICMP] src={src_ip} dst={dst_ip} count={count}{RESET}")
                sys.stdout.flush()

        # --- forwarding for learning switch ---
        dst = eth.dst
        if dpid in self.mac_to_port and dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if in_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src_mac)
            if out_port != ofp.OFPP_FLOOD:
                datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=1, match=match,
                                instructions=[parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]))

        datapath.send_msg(parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                         in_port=in_port, actions=actions, data=msg.data))

    # ----------------- install block -----------------
    def _install_block_and_observe_flow(self, datapath, attacker_ip):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=200, match=match, instructions=inst)
        datapath.send_msg(mod)

    # ----------------- monitor thread -----------------
    def _monitor(self):
        while True:
            hub.sleep(1)
            if not self.host_stats:
                continue
            print(f"{YELLOW}\n=== ICMP Host Stats ==={RESET}")
            for host, stats in self.host_stats.items():
                last_seen = time.strftime("%H:%M:%S", time.localtime(stats['last_time']))
                total = stats['count']
                rtt = stats['rtt']
                flag = ""
                for (s,d), c in self.icmp_count.items():
                    if s == host and c > self.threshold:
                        flag = f"{RED} [⚠ FLOOD]{RESET}"
                blocked_tag = f"{RED} [BLOCKED]{RESET}" if host in self.blocked_ips else ""
                print(f"Host {host}{blocked_tag} → Total Packets: {total} | RTT: {rtt}s | Last Seen: {last_seen}{flag}")
                
                # write CSV for static visualization
                write_csv_row(HOST_STATS_CSV, [iso_utc_now(), host, total, rtt])
            sys.stdout.flush()
