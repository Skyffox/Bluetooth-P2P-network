import logging
import struct
import re
from enum import Enum

# This is used to pack message fields into a binary format.
message_format = struct.Struct('!2HQLB')
chat_message_format = struct.Struct('!1i')


class NetworkTypes(Enum):
    """Message operations class"""
    NETWORK_JOIN_REQUEST = 1
    NETWORK_JOIN_RESPONSE = 2

    JOIN_INFO = 3
    NODES_FOUND_RESULT = 4
    ANNOUNCE_NODE = 5

    BROADCAST_MESSAGE = 6

    DIRECT_MESSAGE = 9
    EXIT = 10
    NO_ROUTE = 11
    EXIST = 12

    SEND_TOP_TO_JOINING_NODE = 13
    SEND_TOP_TO_JOINED_NODE = 14
    TOP_UPDATE = 15
    NODE_DISCONNECTED = 16


class BroadcastTypes(Enum):
    FORWARD = 0
    NOFORWARD = 1


class ChatTypes(Enum):
    JOIN_CHAT = 1
    LEAVE_CHAT = 2

    MESSAGE = 3

    NODES = 4
    NETWORK = 5

    REQUEST_NAMES = 6
    SEND_NAMES = 7

    SEND_FILE = 8
    SEND_NEW_FILE = 9

    PING = 10
    PONG = 11


class CommandTypes(Enum):
    CONNECT = 1
    GUI = 2
    REFRESH = 3
    BACK = 4


def _check_mac_address(sender):
    """
    Checks whether the given mac address is valid.

    Arguments:
    - sender: The mac address of the sender.

    Returns: A boolean value which indicates the validness of a mac address.
    """
    if re.compile("([a-fA-F0-9]{2}[:]?){6}").search(sender):
        return True
    return False


def message_encode(msg_type, msg_sequence, sender_mac: str, message_bytes: bytes, dest_mac: str = "00:00:00:00:00:00",
                   forward: int = 1):
    """
    Encodes message fields into a binary format.

    Arguments:
    - msg_type: The message type.
    - sender_mac: The mac address of the sender.
    - dest_mac: The destination mac address of the message(for direct messages).
    - sequence: The wave sequence number.
    - message: The message with the packet.

    Returns: A binary string in which all parameters are packed.
    """
    if msg_sequence > 1 << 16:
        raise ValueError("Message counter is too large (>%d)" % (1 << 16))

    if not _check_mac_address(sender_mac) or not _check_mac_address(dest_mac):
        raise ValueError("Sender or destination mac address not valid")

    sender_int = int(sender_mac.upper().replace(":", ""), 16)
    dest_int = int(dest_mac.upper().replace(":", ""), 16)

    # Convert the sender int and destination int in a long (8 bytes) and a short (4 bytes).
    # This is because there exist no types for 6 bytes packed data.
    sender_int <<= 16
    sender_int ^= (dest_int >> 32)
    dest_int &= (2 ** 32 - 1)

    return message_format.pack(msg_type.value, msg_sequence, sender_int, dest_int, forward) + message_bytes


def message_decode(buffer):
    """
    Decodes a binary message string.

    :param buffer: The binary string to decode.

    :return: Tuple containing all the unpacked message fields.
             (NetworkType, sender_mac, destination_mac, message_sequence, message_bytes)
    """
    msg_type, msg_sequence, sender_int, dest_int, forward = message_format.unpack(buffer[:17])
    message_bytes = buffer[17:]

    # Convert the long and short back into two mac addresses.
    # This is because there exist no types for 6 bytes packed data.
    dest_int ^= (sender_int & (2 ** 16 - 1)) << 32
    sender_int >>= 16

    sender_hex = "{:012x}".format(sender_int)
    sender_mac = ":".join(sender_hex[i:i + 2] for i in range(0, len(sender_hex), 2))

    dest_hex = "{:012x}".format(dest_int)
    dest_mac = ":".join(dest_hex[i:i + 2] for i in range(0, len(dest_hex), 2))

    return NetworkTypes(msg_type), sender_mac, dest_mac, msg_sequence, forward, message_bytes


def chat_message_encode(chat_type: ChatTypes, message: bytes) -> bytes:
    return chat_message_format.pack(chat_type.value) + message


def chat_message_decode(buffer: bytes) -> (ChatTypes, bytes):
    """
    Decodes a binary message string.

    :param buffer: The binary string to decode.

    :return: A dictionary containing all the unpacked message fields.
    """
    msg_type = chat_message_format.unpack(buffer[:4])[0]
    message_bytes = buffer[4:]

    return ChatTypes(msg_type), message_bytes
