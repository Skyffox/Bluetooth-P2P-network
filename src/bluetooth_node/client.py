from datetime import datetime
import sys

MAX_INT = sys.maxsize
BUFFER_SIZE = 32768


class Client:
    def __init__(self, mac: str, sock):
        self.mac = mac.upper()
        self.socket = sock

        self.accepted = False

        self.total_message_length = BUFFER_SIZE
        self.message = b''
        self.message_length = -1

        self.message_numbers = {}
        self.routing_nodes = [] 

        self.bytes_sent = 0
        self.bytes_received = 0

    def check_valid_message_id(self, message_id: int) -> bool:
        """
        This checks if a message id is valid.
        Requirements for the message id are that it is not a message id that was sent before.
        This is to remove possible duplicate received messages.

        :param message_id: a new message id to be checked
        :return: bool: is valid message id
        """
        if message_id not in self.message_numbers.keys():
            self.message_numbers[message_id] = datetime.now()
            return True
        elif (datetime.now() - self.message_numbers[message_id]).total_seconds() > 120:  # 2 minutes
            self.message_numbers[message_id] = datetime.now()
            return True

        return False
