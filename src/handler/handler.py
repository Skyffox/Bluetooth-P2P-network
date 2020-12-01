import logging
import os
import time
from queue import Queue
from threading import Thread

from src.bluetooth_node.blue_node import BlueNode
from src.monitor import monitor
from src.packets.packets import NetworkTypes, ChatTypes, chat_message_decode, \
    CommandTypes, chat_message_encode, _check_mac_address
from src.monitor import monitor


class Handler(object):
    def __init__(self, data_queue, gui_input: Queue, gui_output: Queue, blue_node: BlueNode, mac: str):
        self.connected_nodes = {}

        self.blue_node = blue_node

        self.mac = mac

        self.data_queue = data_queue
        self.gui_input_queue = gui_input
        self.gui_output_queue = gui_output

        self.username = ""
        self.usernames = {}
        self.file_data = {}
        self.file_folder = "data/"

    def handle_broadcast(self, sender_mac, packet):
        """
        Handles a broadcast message,

        :param sender_mac: The mac address of the destination
        :param packet: The packet to be handled
        """
        chat_type, data = chat_message_decode(packet)

        if chat_type == ChatTypes.MESSAGE:
            message = data.decode("utf-8")
            self.gui_input_queue.put((ChatTypes.MESSAGE, (self._get_username(sender_mac), _clean_message(message))))

        elif chat_type == ChatTypes.JOIN_CHAT:
            message = data.decode("utf-8")
            message = _clean_message(message)
            self.usernames[sender_mac.upper()] = message
            self.gui_input_queue.put((ChatTypes.MESSAGE, ("SYSTEM", message + " has joined chat.")))

    def handle_direct(self, sender_mac, packet):
        """
        Handles a direct message,

        :param sender_mac: The mac address of the destination
        :param packet: The packet to be handled
        """
        chat_type, data = chat_message_decode(packet)

        if chat_type == ChatTypes.REQUEST_NAMES:
            names = ";".join([str(key) + ',' + str(value) for key, value in self.usernames.items()])
            names += ";" + self.mac + "," + self.username
            self.send_direct(ChatTypes.SEND_NAMES, sender_mac, names)

        elif chat_type == ChatTypes.SEND_NAMES:
            message = data.decode("utf-8")
            name_macs = message.split(";")
            self.usernames = {value.split(',')[0]: value.split(',')[1] for value in name_macs if self.username != value.split(',')[1]}

        elif chat_type == ChatTypes.MESSAGE:
            message = data.decode("utf-8")
            self.gui_input_queue.put((ChatTypes.MESSAGE, (self._get_username(sender_mac) + " whispered", message)))

        elif chat_type == ChatTypes.SEND_FILE:
            self.handle_file(sender_mac, data)

        elif chat_type == ChatTypes.SEND_NEW_FILE:
            self.handle_new_file(sender_mac, data)

        elif chat_type == ChatTypes.PING:
            self.handle_ping(sender_mac, data)

        elif chat_type == ChatTypes.PONG:
            time = int(data.decode("utf-8"))
            t = monitor.time_millis() - time
            with open("logs/ping_rtt_3hop.txt", "a+") as f:
                f.write(str(t) + "\n")
            self.gui_input_queue.put((ChatTypes.MESSAGE, ("SYSTEM", "Ping returned with RTT time %f" % (t / 1000.0))))

    def handle_ping(self, sender_mac, data):
        self.send_direct(ChatTypes.PONG, sender_mac, data.decode())
        self.gui_input_queue.put((ChatTypes.MESSAGE, (sender_mac, "Received ping")))

    def handle_file(self, sender_mac, data):
        n = int.from_bytes(data[:2], 'big')

        self.file_data[sender_mac].append((n, data[2:]))
        # Done sending the file, reconstruct.
        if n == self.file_data[sender_mac][0][0]:
            self.gui_input_queue.put((ChatTypes.MESSAGE, ("SYSTEM", "File is done downloading.")))

            byte_data = b"".join([l[1] for l in self.file_data[sender_mac][1:]])
            with open(self.file_folder + self.file_data[sender_mac][0][1], "wb") as f:
                f.write(byte_data)

    def handle_new_file(self, sender_mac, data):
        d = data.decode("utf-8").split(" ")
        self.file_data[sender_mac] = [(int(d[1]), d[0])]
        self.gui_input_queue.put((ChatTypes.MESSAGE,
                                  ("SYSTEM", "%s sent you %s split over %s packets." %
                                   (self.usernames[sender_mac], d[0], d[1]))))

    def handle_message(self, message_type: NetworkTypes, data):
        """
        Handles a message differently according to its message type.

        :param message_type: The given message type
        :param data: The data to be handled
        """
        if message_type == NetworkTypes.JOIN_INFO:
            name, message = data
            self.gui_input_queue.put((ChatTypes.MESSAGE, ("SYSTEM", "Joined server %s at address %s" % (name, message))))

        elif message_type == NetworkTypes.BROADCAST_MESSAGE:
            self.handle_broadcast(*data)

        elif message_type == NetworkTypes.NODES_FOUND_RESULT:
            self.gui_input_queue.put((ChatTypes.NODES, data))

        elif message_type == NetworkTypes.DIRECT_MESSAGE:
            self.handle_direct(*data)

        elif message_type == NetworkTypes.EXIT:
            mac = data
            self.gui_input_queue.put((ChatTypes.MESSAGE, ("SYSTEM", "%s (%s) has left the server" % (self._get_username(mac), mac))))
            if mac in self.usernames:
                del self.usernames[mac]

    def send_broadcast(self, msg_type, line):
        """
        Handles a broadcast command, sends a broadcast message to the all
        connected nodes.

        :param msg_type: The given message type
        :param line: The message to be sent
        """
        packet = chat_message_encode(msg_type, line.encode("utf-8"))
        self.blue_node.send_broadcast_message(packet)

    def send_direct(self, msg_type, dest, line):
        """
        Handles a direct command, sends a direct message to the given
        destination.

        :param msg_type: The given message type
        :param dest: The given destination mac addres
        :param line: The message to be sent
        """
        packet = chat_message_encode(msg_type, line.encode("utf-8"))
        self.blue_node.send_direct(dest, packet)

    def send_file(self, receiver_mac: str, filename: str):
        receiver_mac = self._find_mac_from_name(receiver_mac)
        try:
            file_length = str(os.path.getsize(self.file_folder + filename) // 32000)

            packet = chat_message_encode(ChatTypes.SEND_NEW_FILE, (filename + " " + file_length).encode('utf-8'))
            self.blue_node.send_direct(receiver_mac, packet)

            file = open(self.file_folder + filename, "rb")
            ctr = 0
            while True:
                data = file.read(32000)
                if not data:
                    break

                bytes_ctr = ctr.to_bytes(2, 'big')
                packet = chat_message_encode(ChatTypes.SEND_FILE, bytes_ctr + data)
                self.blue_node.send_direct(receiver_mac, packet)
                ctr += 1

        except IOError as e:
            logging.error("File does not exist.")
            pass

    def list_network(self):
        """
        Handles a list network command, list all the current nodes in the network
        by putting the data to the GUI input queue.
        """
        self.gui_input_queue.put((ChatTypes.NETWORK, self.usernames))

    def list_connected(self):
        """
        Handles a list connected command, list all the current connected nodes
        by putting the data to the GUI input queue.
        """
        client_macs = [client.mac for client in self.blue_node.clients.get_connected_clients()]
        self.connected_nodes = {key: value for key, value in self.usernames.items() if key in client_macs}
        self.gui_input_queue.put((ChatTypes.NETWORK, self.connected_nodes))

    def exec_gui(self, line):
        """
        Handles a gui command differently according to its content.

        :param line: The string to be processed of the GUI.
        """
        command = line.split(' ', 1)[0]

        if command == '!direct' or command == "!pm":
            try:
                data = line.split(' ', 2)
                mac_address = self._find_mac_from_name(data[1])

                if not _check_mac_address(mac_address):
                    self.gui_input_queue.put((ChatTypes.MESSAGE,
                                              ("SYSTEM", "The given username/mac [%s] was invalid." % mac_address)))
                    return

                message = data[2]
                self.send_direct(ChatTypes.MESSAGE, mac_address, message)
            except IndexError as e:
                self.gui_input_queue.put((ChatTypes.MESSAGE,
                                          ("SYSTEM", "Correct syntax: (!direct|!pm) (username|mac) message")))
        elif command == '!list':
            self.list_network()
        elif command == '!l':
            self.list_connected()
        elif command == '!upload':
            data = line.split(' ', 2)
            if len(data) < 3:
                return
            self.send_file(data[1], data[2])
        elif command == "!ping":
            data = line.split(" ", 1)
            if len(data) < 2:
                return

            mac_address = self._find_mac_from_name(data[1])

            if not _check_mac_address(mac_address):
                self.gui_input_queue.put((ChatTypes.MESSAGE,
                                          ("SYSTEM", "The given username/mac [%s] was invalid." % mac_address)))
                return

            t = str(monitor.time_millis())
            self.send_direct(ChatTypes.PING, mac_address, t)
        else:
            print('broadcast')
            self.send_broadcast(ChatTypes.MESSAGE, _clean_message(line))

    def exec_connect(self, input_text: str):
        """
        Handles a connect command, connect to given node by calling the blue node
        function with an index of the input. Furthermore, broadcast it's own
        nickname to all the other nodes in the network and sync the network
        information by requesting the usernames.

        :param input_text: The input to be handled.
        """
        index, nickname = input_text
        self.username = nickname
        if index < 0:
            return

        host_mac = self.blue_node.nearby_nodes[index]["host"]
        self.blue_node.connect_node(index)
        self.send_broadcast(ChatTypes.JOIN_CHAT, nickname)
        self.send_direct(ChatTypes.REQUEST_NAMES, host_mac, "")

    def exec_refresh(self):
        """
        Handles a refresh command, spawn a thread each time this is called to
        search for other nodes in the area. Let the main thread wait for this
        thread to finish. Then send a message to the GUI output queue.
        """
        # Create new thread each time Refresh button is pressed.
        nodes_thread = Thread(target=self.blue_node.find_nodes, name="NodesThread")
        nodes_thread.daemon = True

        nodes_thread.start()

        # Wait for searching for other nodes to finish.
        nodes_thread.join()

        self.gui_input_queue.put((CommandTypes.REFRESH, "(Refresh) Searching for nodes has finished"))

    def exec_back(self):
        pass

    def handle_command(self, data):
        """
        Handles a command differently according to its command type from the
        GUI output queue.

        :param data: The data to be handled.
        """
        if data is not None:
            command, input = data
            if command == CommandTypes.GUI:
                self.exec_gui(input)
            elif command == CommandTypes.CONNECT:
                self.exec_connect(input)
            elif command == CommandTypes.REFRESH:
                self.exec_refresh()
            elif command == CommandTypes.BACK:
                self.exec_back()

    def run(self):
        """
        Read both queues to perform actions.
        """
        while True:
            if not self.data_queue.empty():
                packet = self.data_queue.get()
                if packet is not None:
                    message_type, data = packet
                    self.handle_message(message_type, data)

            if not self.gui_output_queue.empty():
                data = self.gui_output_queue.get()
                self.handle_command(data)

            time.sleep(1 / 180)

    def _get_username(self, mac):
        """
        Returns the username of the corresponding mac address if it exist.

        :param mac: The mac address of the username.
        :return: str: The found username or mac address if it does not exist.
        """
        if mac in self.usernames:
            return self.usernames[mac]
        return mac

    def _find_mac_from_name(self, name: str) -> str:
        """
        Returns the first mac address that's paired with a username, or if none is found, returns the original string.

        :param name: The input string
        :return: The mac address linked to the username, or the original string.
        """
        mac_addresses = [key for key, value in self.usernames.items() if value == name]
        if len(mac_addresses) > 0:
            return mac_addresses[0]
        else:
            return name


def _clean_message(message):
    """
    Cleans a message by removing the 0 bytes from the input message.

    :param message: The message to be cleaned.
    :return: str: The cleaned message.
    """
    return message.split('\x00')[0]
