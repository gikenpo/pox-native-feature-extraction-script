from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time
import sqlite3
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet import ipv4, tcp, udp, icmp

log = core.getLogger()

_flood_delay = 0

class LearningSwitch(object):
    def __init__(self, connection, transparent):
        self.connection = connection
        self.transparent = transparent
        self.macToPort = {}
        self.flowStats = {}
        self.connection_start_time = time.time()
        connection.addListeners(self)
        self.hold_down_expired = _flood_delay == 0

        with sqlite3.connect('poli2.db') as db_connection_thread:
            db_cursor_thread = db_connection_thread.cursor()
            db_cursor_thread.execute('''
                CREATE TABLE IF NOT EXISTS packet_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_mac TEXT,
                    dst_mac TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    flow_duration REAL,
                    transport_protocol TEXT
                )
            ''')
            db_connection_thread.commit()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        src_mac = packet.src
        dst_mac = packet.dst
        packet_count = self.flowStats.get((src_mac, dst_mac), {}).get('packet_count', 0)
        byte_count = self.flowStats.get((src_mac, dst_mac), {}).get('byte_count', 0)
        flow_duration = time.time() - self.connection_start_time

        src_ip = None
        dst_ip = None
        transport_protocol = None

        ipv4_packet = packet.find('ipv4')
        if ipv4_packet:
            src_ip = ipv4_packet.srcip
            dst_ip = ipv4_packet.dstip
            transport_protocol = 'TCP' if isinstance(packet.payload, tcp) else 'UDP' if isinstance(packet.payload, udp) else 'ICMP' if isinstance(packet.payload, icmp) else 'IPv4'
        elif packet.find('ipv6'):
            transport_protocol = 'IPv6'
        elif packet.find('arp'):
            transport_protocol = 'ARP'
        else:
            log.warning("Unknown protocol type")

        src_mac_str = str(src_mac)
        dst_mac_str = str(dst_mac)
        src_ip_str = str(src_ip) if src_ip else None
        dst_ip_str = str(dst_ip) if dst_ip else None

        log.info("PacketIn: Source MAC = %s, Destination MAC = %s, Source IP = %s, Destination IP = %s, Transport Protocol = %s, Packet Count = %s, Byte Count = %s, Flow Duration = %.2f seconds",
                 src_mac_str, dst_mac_str, src_ip_str, dst_ip_str, transport_protocol, packet_count, byte_count, flow_duration)

        with sqlite3.connect('poli2.db') as db_connection_thread:
            db_cursor_thread = db_connection_thread.cursor()
            db_cursor_thread.execute('''
                INSERT INTO packet_info (src_mac, dst_mac, src_ip, dst_ip, packet_count, byte_count, flow_duration, transport_protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (src_mac_str, dst_mac_str, src_ip_str, dst_ip_str, packet_count, byte_count, flow_duration, transport_protocol))
            db_connection_thread.commit()

        def flood(message=None):
            msg = of.ofp_packet_out()
            if time.time() - self.connection_start_time >= _flood_delay:
                if self.hold_down_expired is False:
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding",
                             dpid_to_str(event.dpid))
                if message is not None:
                    log.debug(message)
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            else:
                pass
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        def drop(duration=None):
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration, duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port

        if not self.transparent:
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                drop()
                return

        if packet.dst.is_multicast:
            flood()
        else:
            if packet.dst not in self.macToPort:
                flood("Port for %s unknown -- flooding" % (packet.dst,))
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:
                    log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                                % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                    drop(10)
                    return

                log.debug("installing flow for %s.%i -> %s.%i" %
                          (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port=port))
                msg.data = event.ofp
                self.connection.send(msg)

                # Update flow statistics
                self.update_flow_stats(packet, event, src_mac, dst_mac)

    def update_flow_stats(self, packet, event, src_mac, dst_mac):
        if (src_mac, dst_mac) not in self.flowStats:
            self.flowStats[(src_mac, dst_mac)] = {'packet_count': 0, 'byte_count': 0}

        self.flowStats[(src_mac, dst_mac)]['packet_count'] += 1
        self.flowStats[(src_mac, dst_mac)]['byte_count'] += len(event.ofp)

class l2_learning(object):
    def __init__(self, transparent, ignore=None):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.ignore = set(ignore) if ignore else ()

    def _handle_ConnectionUp(self, event):
        if event.dpid in self.ignore:
            log.debug("Ignoring connection %s" % (event.connection,))
            return
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent)

def launch(transparent=False, hold_down=_flood_delay, ignore=None):
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    if ignore:
        ignore = ignore.replace(',', ' ').split()
        ignore = set(str_to_dpid(dpid) for dpid in ignore)

    core.registerNew(l2_learning, str_to_bool(transparent), ignore)

