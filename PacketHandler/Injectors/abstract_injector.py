import re
from abc import ABCMeta, abstractmethod

from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether


class AbstractInjector:
    __metaclass__ = ABCMeta

    @abstractmethod
    def inject(self, packet):
        # type: (Ether) -> Ether
        pass

    def replace_packet_tcp_payload(self, packet, new_payload):
        payload = packet[TCP].payload
        delta = len(new_payload) - len(payload)

        # Modify the payload to match the length of the original payload
        if delta < 0:
            new_payload += "\n" * -delta  # Pad with new-lines if the payload is too short
        elif delta > 0:
            # Decrease the payload length by replacing two subsequent whitespaces
            progress = True
            while progress and delta > 0:
                # Replace two adjecent spaces by one to shorten the payload
                new_payload = re.sub(r'  ', ' ', new_payload, delta)

                # Compute the new difference in length
                new_delta = len(new_payload) - len(payload)

                # Check if we are still making progress
                if new_delta == delta:
                    progress = False

                # Update delta for the next iteration
                delta = new_delta

            # Check if the substitution of spaces was successful
            if not progress:
                print('Failed substituting packet payload (could not sufficiently shorten payload)')
                return

        # Remove some values from the packet in order to let scapy recompute them
        del packet[TCP].chksum
        del packet[IP].chksum

        # Replace the payload of the packet
        packet[TCP].remove_payload()
        packet[TCP].add_payload(new_payload)
        packet.build()

        return packet
