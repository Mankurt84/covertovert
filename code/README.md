# Covert Storage Channel that exploits Protocol Field Manipulation using Receive Timestamp field in NTP [Code: CSC-PSV-NTP-RECT]

Overview
This project implements a covert channel communication system that utilizes the Receive Timestamp field of the NTP (Network Time Protocol) to encode and transmit binary data covertly. The project consists of two components: A sender that encodes and transmits the message, A receiver that decodes the transmitted message.
The covert channel is established by modifying the least significant 32 bits of the Receive Timestamp field in NTP packets, enabling the transmission of binary data while maintaining protocol validity.

Implementation Details
Sender (send function)

Message Generation:
A random binary message is generated using the generate_random_binary_message_with_logging function.
The message is logged into a specified file (log_file_name)

Encoding:
Each binary bit is encoded into a 32-bit integer, using values below 
2^31 for 0 and values above 2^31 for 1.
These values are embedded in the Receive Timestamp field of NTP packets.

Packet Transmission:
The encoded packets are sent sequentially to the receiver using the send method.


Performance Measurement:
The covert channel capacity is calculated as the number of bits transmitted per second. In this implementation, the capacity was measured as 39 bits/second.

Receiver (receive function)
Packet Sniffing:
NTP packets are captured using Scapy's sniff function.

Decoding:
The covert bits are extracted from the Receive Timestamp field of the captured packets.
Binary bits are decoded into characters, and the received message is reconstructed.

Termination:
When a termination character (".") is detected, the decoded message is logged, and the receiver stops sniffing.

Covert Channel Capacity
The measured covert channel capacity for this implementation is:
39 bits per second
This value was obtained by dividing the total number of transmitted bits by the transmission duration.

Configuration File (config.json)
The config.json file defines all configurable parameters for the sender and receiver.

Parameters:
covert_channel_code: Identifier for the covert channel type (e.g., "Code: CSC-PSV-NTP-RECT").

Sender Parameters:
source_ip : IP address of the sender
destination_ip : IP address of the receiver
log_file_name: File name to log sent messages for debugging and validation.

Receiver Parameters:
log_file_name: File name to log sent messages for debugging and validation.