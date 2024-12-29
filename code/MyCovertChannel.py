from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, NTP,sniff
import random
import time
class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        Initializes the MyCovertChannel class with variables to store received bits and messages,
        a stop event.
        """
        self.received_bits = "" 
        self.received_messages = ""  
        self.stop_event = False 

    def send(self, log_file_name,source_ip, destination_ip):
        """
        Encodes a random binary message into the `recv` field of NTP packets and sends them to the destination.
        
        Steps:
        - Generate a random binary message and log it.
        - Create an NTP packet with the specified source and destination IPs.
        - Encode each bit of the message into the `recv` field of the packet.
        - Transmit the packets one bit at a time.
        - Measure and print the covert channel capacity in bits per second.
        """
        
        binary_message = self.generate_random_binary_message_with_logging(log_file_name,16,16)
        ntp_request = self.create_ntp_packet(source_ip, destination_ip)
        time_start = time.time()
   
        for bit in binary_message:
            field_value = self.encode_bit_in_field(bit)
            ntp_request.recv = field_value  
            super().send(ntp_request)
        time_end = time.time()
        capacity = len(binary_message) / (time_end - time_start)
        print(f"Covert channel capacity: {capacity:.2f} bits per second")
    def receive(self, log_file_name):
        """
        Listens for incoming NTP packets and decodes binary bits from their `recv` field.
        
        Steps:
        - Define a decoding function to extract bits from received packets.
        - Set a stop condition to halt sniffing when a complete message is received.
        - Use Scapy's `sniff` function to capture packets and decode the message.
        """
        def decode_packet(packet):
            return self._decode_packet(packet,log_file_name)
        def stop_condition(_):
            return self.stop_event

        sniff(filter="udp and port 123", prn=decode_packet,stop_filter=stop_condition)

        
    def encode_bit_in_field(self, bit):
        """
        Encodes a binary bit ('0' or '1') into range of integer values (0,2^32-1).
        
        Returns:
        int: An integer representing the encoded bit.

        - '0' maps to a random value in [0, 2^31 - 1].
        - '1' maps to a random value in [2^31, 2^32 - 1].
        """
        if bit == '0':
            return random.randint(0, 2**31-1)
        elif bit == '1':
            return random.randint(2**31, 2**32-1)

    def decode_bit_from_field(self, field_value):
        """
        Decodes a binary bit ('0' or '1') from the range of integer values.
        
        Returns:
            str: The decoded binary bit ('0' or '1').
        """
        if field_value < 2**31:
            return '0'
        else:
            return '1'

    def create_ntp_packet(self, source_ip, destination_ip):
        """
        Creates an NTP packet with the specified source and destination IPs.
        
        Args:
            source_ip (str): Source IP address for the packet.
            destination_ip (str): Destination IP address for the packet.
        
        Returns:
            Scapy Packet: The created NTP packet.
        """
        ntp_request = IP(src=source_ip, dst=destination_ip) / UDP(sport=123, dport=123) / NTP()
        return ntp_request
    def _decode_packet(self, packet, log_file_name):
        """
        Decodes a received NTP packet to extract binary bits and construct the message.
        Steps:
        - Check if the packet contains an NTP layer.
        - Decode the bit from the `recv` field and append it to `received_bits`.
        - Convert every 8 bits into a character and append it to `received_messages`.
        - Stop sniffing when the message ends with a period ('.').
        - Log the complete message to the log file.
        """
        if packet.haslayer(NTP):
            field_value = packet[NTP].recv
            decoded_bit = self.decode_bit_from_field(field_value)
            self.received_bits += decoded_bit

            if len(self.received_bits) % 8 == 0:
                char = self.convert_eight_bits_to_character(self.received_bits[-8:])
                self.received_messages += char
                if char == '.':
                    self.log_message(self.received_messages, log_file_name)
                    self.stop_event = True
