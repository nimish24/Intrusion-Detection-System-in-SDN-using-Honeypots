from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
import time
from pox.lib.addresses import IPAddr, EthAddr

# Hosts hash table key: HostIP Value: MAC
hosts = {}

hosts["10.0.0.1"] = "00:00:00:00:00:01";
hosts["10.0.0.2"] = "00:00:00:00:00:02";
hosts["10.0.0.3"] = "00:00:00:00:00:03";
hosts["10.0.0.4"] = "00:00:00:00:00:04";        			

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class LearningSwitch (object):
  
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

    # Now add entries for ARP requests and DHCP requests.
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(dl_type = pkt.ethernet.ARP_TYPE);
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match(nw_proto = 17, tp_src = 67 , tp_dst = 68 );
    msg.idle_timeout = of.OFP_FLOW_PERMANENT;
    msg.hard_timeout = of.OFP_FLOW_PERMANENT;
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    print "Installed flow entries\n"

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def send_to_honeypot ():
	msg = of.ofp_packet_out()
	msg.actions.append(of.ofp_action_output(port = 4))
	msg.in_port = event.port
	msg.data = event.ofp
	self.connection.send(msg)	
	print "Malicious packets processed and forwarded to honeypot"
   
    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
	print "I am getting dropped"
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
	print "I am getting dropped 2"
        self.connection.send(msg)

	# If ARP packet, then check if the packet is spoofed. If its not, then continue with the flow.
    if packet.type == packet.ARP_TYPE:		
		print "Its ARP\n"
		if packet.payload.opcode == pkt.arp.REPLY :
			print "1st condition"
			src_mac_eth = packet.src
			dst_mac_eth = packet.dst
			src_ip_arp = packet.payload.protosrc
			src_mac_arp = packet.payload.hwsrc 
			dst_ip_arp = packet.payload.protodst

			print "Source MAC : "+str(src_mac_arp)+"\n";
			print "Dest MAC : "+str(dst_mac_eth)+"\n";
			print "Source IP : "+str(src_ip_arp)+"\n";
			print "Source DST : "+str(dst_ip_arp)+"\n";
			print src_mac_eth
			print src_mac_arp
			
			# Check whether this IP exists in the hash table
			
			if src_mac_eth != src_mac_arp :
				print "Spoofing detected"
				send_to_honeypot()
				print "Malicious data forwarded to Honeypot"
				return
			else:
				print "Table MAC : "+hosts[str(src_ip_arp)]+" and mac "+str(src_mac_arp)+"\n";
				if EthAddr(hosts[str(src_ip_arp)]) != src_mac_arp:
					print "Spoofing detected: IP and MAC not matched\n"
					send_to_honeypot()
					print "Malicious data forwarded to Honeypot"
					return
				else:
					# Valid Arp Packet
					print "Valid ARP\n";
					# Check if the dest host is already there in the network
					if dst_ip_arp not in hosts.keys():
						# Spoofing detected
						print "Spoofing detected: Dest host ip not in table\n"
						#drop()
						print "Malicious data forwarded to Honeypot"
						send_to_honeypot()
						return
					else:
						if str(dst_mac_eth) == "ff:ff:ff:ff:ff:ff":
							# Now flood the packets to all the other ports
							print "Flooding the packets\n"
						else:
							# ARP Request should be broadcast. Some are unicast sometimes.
							print "Unicast legitimate ARP request\n"

    self.macToPort[packet.src] = event.port

    if not self.transparent:
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop()
	print "I am getting dropped 1"
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
          drop(50)
          return
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)


class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))
