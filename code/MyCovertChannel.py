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
        self.received_bits = ""  # Keeps track of all received bits
        self.received_messages = ""  # Stores decoded characters
        self.stop_event = False 

    def send(self, log_file_name,source_ip, destination_ip):
        """
        Sends a binary message by encoding the message bits into a protocol-specific field (4-bit field in this case).
        """
        # Create NTP request packet
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        ntp_request = self.create_ntp_packet(source_ip, destination_ip)
        time_start = time.time()
        # Send each bit of the binary message by encoding it in the 4-bit field
        for bit in binary_message:
            field_value = self.encode_bit_in_field(bit)
            ntp_request.recv = field_value  # Modify the protocol-specific field (e.g., Receive Timestamp)

            # Send the modified NTP packet
            super().send(ntp_request)
        time_end = time.time()
        capacity = len(binary_message) / (time_end - time_start)
        print(f"Covert channel capacity: {capacity:.2f} bits per second")
    def receive(self, log_file_name):
        """
        Receives the NTP packets and decodes the 4-bit field to extract the binary message.
        """
        decoded_message = []

        def decode_packet(packet):
            return self._decode_packet(packet,log_file_name)
        def stop_condition(_):
            return self.stop_event

        sniff(filter="udp and port 123", prn=decode_packet,stop_filter=stop_condition)

        # Join the decoded bits to reconstruct the binary messag
    def encode_bit_in_field(self, bit):
        """
        Encodes a single bit into the 4-bit protocol field.
        """
        if bit == '0':
            # Use values less than 8 for 0
            return random.randint(0, 2^31-1)
        elif bit == '1':
            # Use values greater than or equal to 8 for 1
            return random.randint(2^31, 2^32-1)

    def decode_bit_from_field(self, field_value):
        """
        Decodes a 4-bit field value to extract the binary message bit.
        """
        if field_value < 2^31:
            return '0'
        else:
            return '1'

    def create_ntp_packet(self, source_ip, destination_ip):
        """
        Creates a basic NTP packet with the given client and server IP addresses.
        """
        ntp_request = IP(src=source_ip, dst=destination_ip) / UDP(sport=123, dport=123) / NTP()
        return ntp_request
    def _decode_packet(self, packet, log_file_name):
        """
        Function to process each received NTP packet, decode the bits and reconstruct the message.
        """
        if packet.haslayer(NTP):
            # Extract the field value from the NTP packet
            field_value = packet[NTP].recv
            # Decode the bit based on the field value
            decoded_bit = self.decode_bit_from_field(field_value)
            self.received_bits += decoded_bit

            # If we've received 8 bits, convert them to a character
            if len(self.received_bits) % 8 == 0:
                char = self.convert_eight_bits_to_character(self.received_bits[-8:])
                self.received_messages += char

                # If the character is a dot, log the message and stop receiving
                if char == '.':
                    self.log_message(self.received_messages, log_file_name)
                    self.stop_event = True
