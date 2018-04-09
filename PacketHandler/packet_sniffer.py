import threading

from scapy.all import sniff
from scapy.layers.l2 import Ether, sendp

from PacketHandler.Filters.composite_filter import CompositeFilter
from ip_to_mac_mapper import IpToMacMapper
from scapy import config


class PacketSniffer(threading.Thread):

    def __init__(self, attacker_ips, ip_to_mac, output_frame=None, network_interface=config.conf.iface):
        # type: (list, IpToMacMapper, str) -> self
        super(PacketSniffer, self).__init__()
        self._network_interface = network_interface
        self._attacker_ips = attacker_ips
        self._ip_to_mac = ip_to_mac
        self.output_frame = output_frame

        self._stored_packets = []
        self.packet_filter = CompositeFilter()
        self.packet_injectors = []

    def run(self):
        sniff(
            iface=self._network_interface,
            store=0,
            prn=self._handle_packet
        )

    def get_stored_packets(self):
        return self._stored_packets

    def _handle_packet(self, packet):
        # type: (Ether) -> None

        # Get the string version of all filters
        as_string = self.packet_filter.to_string(packet)
        if as_string is not None:
            if self.output_frame is not None:
                update = "\n" + as_string + "\n"
                self.output_frame.update_output(update, append=True)
            else:
                print("vvvvvvvvvvvvvvvvvvvvvv")
                print(as_string)
                print("^^^^^^^^^^^^^^^^^^^^^^")

        # Only consider packets with an IP part.
        ip = packet.getlayer('IP')
        if ip is not None:
            # Do not relay packets for or from ourselves
            if ip.dst in self._attacker_ips or ip.src in self._attacker_ips:
                return

            # Try to lookup the actual mac address of the package
            target_dst = self._ip_to_mac.get(ip.dst)
            if target_dst is None:
                if self.output_frame is not None:
                    status = '\nreceived a packet for an unknown host (%s)\n' % ip.dst
                    self.output_frame.update_output(status, append=True)
                else:
                    print('received a packet for an unknown host (%s)' % ip.dst)
                return

            # Ignore packets which are already targeted correctly, since either we generated
            # them or they are legitimate packets originating from our own host.
            if target_dst.lower() != packet.dst.lower():

                # Allow the injectors to modify the packet
                for injector in self.packet_injectors:
                    result = injector.inject(packet.copy())
                    if result is not None:
                        packet = result

                if self.output_frame is not None:
                    status = '\nredirecting a packet from %s (%s) to %s\n' % (packet.dst, ip.dst, target_dst)
                    self.output_frame.update_output(status, append=True)
                else:
                    print('redirecting a packet from %s (%s) to %s' % (packet.dst, ip.dst, target_dst))
                packet.dst = target_dst
                sendp(packet)
