"""
This file contains the class which is used to connect to the bluetooth network in the area.
"""

import logging
import pickle
import sys

import networkx as nx
import select
import json
import time

from queue import Queue
from typing import List, Dict
from threading import Thread, Lock
from datetime import datetime

from src.bluetooth_node.client import Client, BUFFER_SIZE, MAX_INT
from src.bluetooth_node.client_list import ClientList
from src.packets.packets import NetworkTypes, message_encode, message_decode
from options import *

if len(sys.argv) == 4:
    sim = True
    from src.bluetooth_node.rfcomm_sim import BluetoothSocket, RFCOMM, PORT_ANY, BluetoothError, setup_simulation
    setup_simulation(sys.argv[Args.simulation])

    def advertise_service(*argv, service_id):
        pass

    def find_service(*argv):
        pass
else:
    sim = False
    from bluetooth import BluetoothSocket, RFCOMM, PORT_ANY, BluetoothError, advertise_service, find_service


class BlueNode:
    def __init__(self, uuid: str, queue: Queue, mac: str):
        # Set node status for monitoring
        self.status = "starting"

        self.clients = ClientList()

        self.heartbeat_network = {'11:22:33:44:55:66': datetime.now()}

        self.nearby_nodes = []  # type: List[Dict]
        self.new_nearby_nodes = []  # type: List[Dict]

        self.graph = nx.Graph()
        self.graph_lock = Lock()

        self.queue = queue

        # Initialize sequence number to identify unique messages. Increments
        # with each message.
        self.sequence_number = 0

        # Set up server socket for incoming connections.
        self.server_sock = BluetoothSocket(RFCOMM)
        self.server_sock.bind((mac, PORT_ANY))
        # Maximum queue size of to be processed connections from other nodes.
        self.server_sock.listen(1000)

        self.mac = mac
        logging.debug("MAC: %s", self.mac)

        self.set_options()

        if self.broadcast_method == BroadcastMethod.normal:
            self.send_broadcast = self.send_normal_broadcast
        elif self.broadcast_method == BroadcastMethod.optimized:
            self.send_broadcast = self.send_optimized_broadcast

        # logging.info("{} {} {}".format(self.topology_detection_method, self.broadcast_method, self.routing_method))
        # Thread for listening to incoming clients.
        self.listen_thread = Thread(target=self.listen, name="ListenThread")
        self.listen_thread.daemon = True

        # Thread to check for inactive peers.
        self.heartbeat_thread = Thread(target=self.heartbeat, name="HeartbeatThread")
        self.heartbeat_thread.daemon = True

        self.uuid = uuid

        self.total_received_bytes = 0
        self.total_sent_bytes = 0

        self.received_msg_seq_nums = {}
        self.write = logging.info

        self.connecting = False

    def set_options(self):
        """
        Each command line argument indicates that certain algorithms should be used in BlueNode. Accordingly this
        is written to variables which BlueNode uses to actually use these algorithms.

        :return: None
        """
        arg = int(sys.argv[Args.arg])

        if arg == 0:
            self.topology_detection_method = TopologyDetectionMethod.heartbeat
            self.broadcast_method = BroadcastMethod.normal
            self.routing_method = RoutingMethod.broadcast
            logging.info("Heartbeat & Normal broadcasting & Broadcast routing")
        elif arg == 1:
            self.topology_detection_method = TopologyDetectionMethod.on_change
            self.broadcast_method = BroadcastMethod.normal
            self.routing_method = RoutingMethod.direct
            logging.info("On_change & Normal broadcasting & Direct routing")
        elif arg == 2:
            self.topology_detection_method = TopologyDetectionMethod.on_change
            self.broadcast_method = BroadcastMethod.optimized
            self.routing_method = RoutingMethod.direct
            logging.info("On_change & Optimized broadcasting & Direct routing")
        elif arg == 3:
            self.topology_detection_method = TopologyDetectionMethod.on_change
            self.broadcast_method = BroadcastMethod.optimized
            self.routing_method = RoutingMethod.broadcast
            logging.info("On_change & Optimized broadcasting & Broadcast routing")

    def run(self):
        """
        1. a. Looks for another node running this application.
           b. Creates a connection to this other node. As a result a socket object
              is created. Data can be send trough the connection with this socket.
           c. Saves {port, name address} of the other node in the connection in
              the connected_nodes dictionary using the earlier created socket as
              key.
        2. Places server connection socket and uuid in SPD server to allow
           discovery of this application by other devices.
        3. Starts the listen thread. In this thread requests for connections, by
           other nodes, waiting at the server socket are asynchronously processed.

           Each request is processed as follows:
           a. Create a connection. This results in a socket and info about the
              other node.
           b. Just like in 1c, the info is saved in the connected_nodes dictionary
              using the socket as key.
        4. Simultaneous to the listen thread, the main thread looks continuously
           at sockets of active connections in the connected_nodes dictionary, to
           if necessary receive data from any of the connections.
        """
        logging.info("Looking for other nodes...")

        # Set standard nearby nodes, which make it easier for testing.
        if not sim:
            self.nearby_nodes = [{
                "host": "E4:B3:18:82:66:7F",
                "name": "julius",
                "port": 1
            }, {
                "host": "00:09:DD:50:8C:D0",
                "name": "ruben",
                "port": 1
            }, {
                "host": "94:B8:6D:F9:94:AC",
                "name": "duncan",
                "port": 1
            }, {
                "host": "D8:FC:93:14:F4:B4",
                "name": "joey",
                "port": 1
            }, {
                "host": "B8:27:EB:5E:04:16",
                "name": "rubens_pi",
                "port": 1
            }]
        else:
            self.nearby_nodes = BluetoothSocket.neighbor_nodes

        # Remove own MAC-address from list.
        self.nearby_nodes = [d for d in self.nearby_nodes if d.get('host') != self.mac]

        with open('nodes.json', 'w') as outfile:
            json.dump(self.nearby_nodes, outfile, sort_keys=True, indent=4)

        # Read all the previously existing connections made.
        with open('nodes.json', 'r') as file:
            self.nearby_nodes = json.load(file)

        logging.info("Nodes in reach: {}".format([x["host"] for x in self.nearby_nodes]))

        self.queue.put((NetworkTypes.NODES_FOUND_RESULT, self.nearby_nodes))

        logging.info("Advertising service.")
        advertise_service(self.server_sock, "BlueNode", service_id=self.uuid)

        self.listen_thread.start()

        if self.topology_detection_method == TopologyDetectionMethod.heartbeat:
            logging.info("Starting heartbeat thread.")
            self.heartbeat_thread.start()

        self.status = "idle"
        self.handle_clients()

    def kill(self):
        """
        Kill connection to all clients.
        """
        for sock in self.clients.get_client_sockets():
            sock.close()
        self.server_sock.close()

    def listen(self):
        """
        Listens to connecting nodes from the area.
        """
        while True:
            client_sock, client_info = self.server_sock.accept()

            # This node was already accepted in the network.
            if client_info[0] in self.clients.get_client_macs():
                print("added existing client")
                self.clients.get_client_by_mac(client_info[0]).socket = client_sock
            # This is a new node in the network.
            else:
                self.clients.add_client(Client(client_info[0], client_sock))
            logging.debug("Accepted connection from {}".format(client_info[0]))

    def heartbeat(self):
        """
        Periodically checks for inactive peers. Each 2 seconds, it will loop
        through the dictionary of all currently found peers(locally/remotely).
        When the difference of the timestamp of a peer and the current time
        exceeds a specific value, it will be regarded as inactive and will be
        removed from the peer list.
        """
        timeout = 9
        heartbeat_period = 3
        while True:

            time.sleep(heartbeat_period)
            for mac, timestamp in list(self.heartbeat_network.items()):
                if (datetime.now() - timestamp).total_seconds() > timeout:
                    client = self.clients.get_client_by_mac(mac)
                    if client is not None:
                        self.clients.remove_client(client)

                    del self.heartbeat_network[mac]
                    self.queue.put((NetworkTypes.EXIT, mac))

            packet = message_encode(NetworkTypes.EXIST, self.new_sequence_nr(), self.mac, b'')
            self.send_broadcast(packet)

    def send(self, sock, data: bytes) -> None:
        """
        Send data to a socket.
        Splits the data into multiple packets if it is too large to be sent all at once.

        :param sock: socket to which you want to send data
        :param data: the data to be sent
        """
        packet = (len(data)).to_bytes(2, 'big') + data

        tot_sent = self.disconnection_handler(sock, sock.send, packet)
        if tot_sent is None:
            # Client disconnected
            return

        while tot_sent < len(packet):
            n_sent = self.disconnection_handler(sock, sock.send, packet[tot_sent:])
            if n_sent is None:
                # Client disconnected
                return

            tot_sent += n_sent

        # For monitoring.
        n_bytes = len(packet)
        self.total_sent_bytes += n_bytes
        self.clients.get_client_by_sock(sock).bytes_received += n_bytes

    def recv(self, sock) -> List[bytes]:
        """
        Receive data from socket.
        Combines received data into the total bytestream as the sender sent it.

        :param sock: socket from which you want to receive data
        :return: None if message not complete, else message
        """
        client = self.clients.get_client_by_sock(sock)

        data = self.disconnection_handler(sock, sock.recv, BUFFER_SIZE)

        if data is None:
            return []

        # For monitoring.
        client.bytes_sent += len(data)
        self.total_received_bytes += len(data)

        handled_data = False

        messages = []

        while not handled_data:
            if client.message_length == -1:
                # Ready to receive a new message.
                client.total_message_length = int.from_bytes(data[0:2], 'big')
                client.message = data[2:]
                client.message_length = len(data) - 2
            else:
                # If all data for a message hasn't been received in the last call of recv, the current received buffer
                # is appended.
                client.message += data
                client.message_length += len(data)

            handled_data = True

            # When the message is fully received
            if client.message_length >= client.total_message_length:
                # There could be other messages in the current buffer.
                msg = client.message[0:client.total_message_length]
                data = client.message[client.total_message_length:]
                client.message_length = -1
                client.message = b''
                client.total_message_length = BUFFER_SIZE

                messages.append(msg)

                # Process the message(s) in the leftover portion.
                if len(data) > 0:
                    handled_data = False

        return messages

    def disconnection_handler(self, sock, func, *args):
        """
        A receive or send should be performed trough this function such that disconnects a registered properly in
        internal state.

        :param sock: The socket on which a recv or send is performed.
        :param func: Should be sock.recv or sock.send.
        :param args: Arguments for func
        :return: func return value or None in case of a disconnect
        """
        result = None
        try:
            result = func(*args)
        except BluetoothError as ex:
            err_val = ex.args[0][1:4]
            logging.debug("BluetoothError %s thrown." % err_val)

            if err_val == "104":
                client = self.clients.get_client_by_sock(sock)
                logging.info("Client {} has disconnected.".format(client))
                self.clients.remove_client(client)
                self.queue.put((NetworkTypes.EXIT, client.mac))

                if self.topology_detection_method == TopologyDetectionMethod.on_change:
                    with self.graph_lock:
                        self.graph.remove_node(client.mac)

                    logging.debug("Topology: {}".format(self.graph.edges()))

                self.send_packet(NetworkTypes.NODE_DISCONNECTED, data=client.mac.encode())
            else:
                # Raise the error again.
                raise BluetoothError(ex)
        return result

    def find_nodes(self):
        """
        Looks for other nodes nearby running this application and if possible
        connects to one random node. Puts the results in the data queue to be
        read in GUI for selecting the node to establish connection. None if
        no other nodes running this application have been found. A tuple of
        socket and {port, name, address} if there is node. The socket is the
        access point of this node to the connection. The dictionary contains
        info of the other node.

        :return: (socket, {port, name, address}) :
        """
        logging.info("Finding nearby nodes.")
        # Find other nodes with specific uuid.
        self.new_nearby_nodes = find_service(uuid=self.uuid)

        if len(self.new_nearby_nodes) == 0:
            logging.info("No nodes in area.")
        else:
            logging.info("Nodes found, you may go to chat")

            # Compare the hosts that have been found with previously recorded hosts.
            nodes = [[item for key, item in node.items() if key == "host"] for node in self.nearby_nodes]
            new_nodes = [[item for key, item in node.items() if key == "host"] for node in self.new_nearby_nodes]

            # Check if hosts already exist and flat out the list.
            new_hosts = [host for host in new_nodes if host not in nodes]
            flat_hosts = [item for sublist in new_hosts for item in sublist]

            new_nodes = []

            # Search for all new connections.
            for node in self.new_nearby_nodes:
                for key, item in node.items():
                    if key == "host" and item in flat_hosts:
                        new_nodes.append(node)

            # Add new nodes
            self.nearby_nodes += new_nodes

            # Send new connections to the json file.
            with open('nodes.json', 'w') as outfile:
                json.dump(self.nearby_nodes, outfile, sort_keys=True, indent=4)

        self.queue.put((NetworkTypes.NODES_FOUND_RESULT, self.nearby_nodes))

    def connect_node(self, list_index):
        """
        Connects to a given node in nearby found node based on the list index.

        :param list_index: The index of nearby nodes list where we want to connect
        """
        node = self.nearby_nodes[list_index]

        host = node["host"]
        port = node["port"]

        # Create the client socket.
        sock = BluetoothSocket(RFCOMM)
        sock.connect((host, port))

        if host not in self.clients.get_client_macs():
            self.clients.add_client(Client(host, sock))
        else:
            self.clients.get_client_by_mac(host).socket = sock

        if self.broadcast_method == BroadcastMethod.optimized:
            with self.graph_lock:
                self.graph.add_edge(self.mac, host)
            self.connecting = True
        # Handshake protocol.
        logging.info("Sending a connection request to {} at {}".format(host, port))
        self.send_login_request(sock)
        logging.info("Sending connection request done....")

    def latch_node(self, latch_mac, port):
        """
        Latches to a node with the given mac address.

        :param latch_mac: The mac address of the target latch node.
        :param port: The port of the socket.
        """
        logging.info("Latching to {}".format(latch_mac))
        client = self.clients.get_client_by_mac(latch_mac)
        # Can not latch when this node is unknown in the current network.
        if client is None:
            return

        # Create the client socket.
        sock = BluetoothSocket(RFCOMM)

        try:
            sock.connect((latch_mac, port))
            client.socket = sock
            if self.topology_detection_method == TopologyDetectionMethod.on_change:
                with self.graph_lock:
                    self.graph.add_edge(self.mac, latch_mac)
                self.share_topology(NetworkTypes.TOP_UPDATE)
            logging.debug("Successfully latched\nDirectly connected nodes: {}".format([x.mac for x in self.clients.get_connected_clients()]))
        except BluetoothError as ex:
            err_val = ex.args[0][1:4]

            if err_val == "112":
                logging.info("Latch failed as host is not in reach")

    def send_login_request(self, sock):
        """
        Sends a LOGIN request message to the entry node.

        :param sock: The socket of the sender.
        """
        packet = message_encode(NetworkTypes.NETWORK_JOIN_REQUEST, self.new_sequence_nr(), self.mac, b'')
        self.send(sock, packet)

    def receive_login_response(self, sock) -> bool:
        """
        Receives a LOGIN response message from the entry node. Sync with the
        network if the response message was a list of mac addresses of the entry
        node.

        :param sock: The socket of the sender.
        :return: bool: Whether the join response valid was accepted.
        """
        logging.debug("Receiving packet from entry node")
        packets = self.recv(sock)

        for packet in packets:
            msg_type, sender_mac, dest_mac, msg_sequence, _, message = message_decode(packet)
            logging.debug("Decoded packet: msg_type:[%s], sender_mac:[%s], msg_sequence:[%d], msg: [%s]" %
                          (msg_type, sender_mac, msg_sequence, message))
            if msg_type != NetworkTypes.NETWORK_JOIN_RESPONSE or message is None:
                self.clients.remove_client(self.clients.get_client_by_mac(sender_mac))
                return False

            mac_nodes_list = pickle.loads(message)
            for mac_node in mac_nodes_list:
                if mac_node.mac not in self.clients.get_client_macs():
                    self.clients.add_client(mac_node)

            return True

    def send_normal_broadcast(self, packet, sender_sock: BluetoothSocket = None):
        """
        Broadcasts a packet to its connected nodes. When a sender sock
        is given, it will not broadcast the message back to its sender.

        :param packet: The packet to be send
        :param sender_sock: The sock of the sender
        """
        if sender_sock:
            for sock in self.clients.get_client_sockets():
                if sock == sender_sock:
                    continue
                self.send(sock, packet)
        else:
            for sock in self.clients.get_client_sockets():
                self.send(sock, packet)

    def find_mpr_nodes(self):
        """
        Finds MPR nodes of this node according to it's local topology. This is a subset of this nodes neighborhood
        which can reach all the 2-hop neighbors.

        :return: MPR nodes of this node.
        """
        hop2neighborhood = [x[0] for x in nx.single_source_shortest_path_length(self.graph, self.mac, cutoff=2).items()
                            if x[1] == 2]
        isolated_nodes = list(filter(lambda x: self.graph.degree(x[0]) == 1, hop2neighborhood))
        non_isolated_nodes = list(set(hop2neighborhood) - set(isolated_nodes))
        neighborhood = list(self.graph.neighbors(self.mac))
        mpr_nodes = []

        # All 2-hop neighbors which are only reachable by one neighbor are set as MPR nodes.
        while isolated_nodes:
            current_node = isolated_nodes.pop(0)
            mpr_node = next(self.graph.neighbors(current_node))
            mpr_node_neighborhood = list(self.graph.neighbors(mpr_node))
            non_isolated_nodes = list(set(non_isolated_nodes) - set(mpr_node_neighborhood))
            isolated_nodes = list(set(isolated_nodes) - set(mpr_node_neighborhood))
            mpr_nodes.append(mpr_node)

        possible_mpr_nodes = list(set(neighborhood) - set(mpr_nodes))

        # Until all 2-hop neighbors have been reached by MPR nodes leftover neighbors are selected as MPR nodes
        # iteratively. In each iteration a neighbor is chosen as MPR node when it relatively reaches the most
        # 2-hop neighbors.
        while non_isolated_nodes:
            mpr_node = None
            max_reachability = 0

            for possible_mpr_node in possible_mpr_nodes:
                hop2_reachability = len(set(self.graph.neighbors(possible_mpr_node)) & set(non_isolated_nodes))

                if hop2_reachability > max_reachability:
                    mpr_node = possible_mpr_node
                    max_reachability = hop2_reachability

            mpr_nodes.append(mpr_node)
            non_isolated_nodes = list(set(non_isolated_nodes) - set(self.graph.neighbors(mpr_node)))
            possible_mpr_nodes.remove(mpr_node)

        return mpr_nodes

    def send_optimized_broadcast(self, packet, sender_sock: BluetoothSocket = ""):
        """
        Sends a broadcast using MPR nodes. It selects MPR nodes and subsequently sets the forward field to 1
        for these nodes. For all non-MPR nodes this field is set to 0. When this node is still in the process of
        connecting normal broadcasting is used. This is because the topology isn't updated and nodes might
        be set as non-MPR nodes while they should be causing not the entire network to receive the broadcast.

        :param packet: The packet to be send
        :param sender_sock: The sock of the sender which should be ignored.
        :return: None
        """
        msg_type, send_mac, dest_mac, mess_seq, forward, mes_bytes = message_decode(packet)
        logging.info("Optimized processing of broadcast of type: {}".format(msg_type))

        if self.connecting:
            logging.info("Still connecting so sending normal broadcast to only neighbor.")
            self.send_normal_broadcast(packet, sender_sock)
            return

        if forward == 0:
            logging.info("Not forwarding")
            return

        logging.info("Forwarding.")

        forward_packet = packet
        noforward_packet = message_encode(msg_type, mess_seq, send_mac, mes_bytes, dest_mac, forward=0)

        with self.graph_lock:
            mpr_nodes = self.find_mpr_nodes()

        neighborhood = [x.mac for x in self.clients.get_connected_clients()]
        noforward_nodes = list(set(neighborhood) - set(mpr_nodes))
        logging.info("MPR_NODES: {} NO_FORWARD_NODES:{}".format(mpr_nodes, noforward_nodes))
        for mpr_node in mpr_nodes:
            if mpr_node == send_mac and sender_sock == "":
                continue
            self.send(self.clients.get_client_by_mac(mpr_node).socket, forward_packet)

        for noforward_node in noforward_nodes:
            if noforward_node == send_mac and sender_sock == "":
                continue
            self.send(self.clients.get_client_by_mac(noforward_node).socket, noforward_packet)

    def send_broadcast_message(self, data):
        """
        Broadcasts input data to all connected nodes.
        Only to be used for the handler to broadcast a message over the network.

        :param data: input data to be sent
        """
        packet = message_encode(NetworkTypes.BROADCAST_MESSAGE, self.new_sequence_nr(), self.mac, data)
        self.send_broadcast(packet)

    def send_direct(self, dest_mac, data):
        """
        Sends a direct message to the destination mac.

        :param dest_mac: Mac address of the receiver.
        :param data: Message to be broadcast.
        """
        packet = message_encode(NetworkTypes.DIRECT_MESSAGE, self.new_sequence_nr(), self.mac, data, dest_mac=dest_mac)

        client = self.clients.get_client_by_mac(dest_mac)
        if client is not None and client.socket is not None:
            self.send(client.socket, packet)
            return

        if self.route_direct(self.mac, dest_mac, packet) is False:
            logging.debug("No route")

    def route_direct(self, sender_address: str, dest_address: str, packet: bytes, sender_sock=None):
        """
        Directs a packet with a given routing algorithm.

        :param sender_sock: The socket of the sending client
        :param sender_address: Sender bluetooth address
        :param dest_address: Destination bluetooth address
        :param packet: The packet of the message
        :return: False if this thread is origin of direct message and no route is possible, None otherwise.
        """
        if self.routing_method == RoutingMethod.broadcast:
            logging.info("Broadcasting direct message...")
            self.send_broadcast(packet, sender_sock)
        elif self.routing_method == RoutingMethod.direct:
            logging.info("Routing packet from {} to {}".format(sender_address, dest_address))
            with self.graph_lock:
                if nx.has_path(self.graph, self.mac, dest_address):
                    next_hop_mac = nx.shortest_path(self.graph, self.mac, dest_address)[1]
                    logging.info("Next hop: {}".format(next_hop_mac))
                    self.send(self.clients.get_client_by_mac(next_hop_mac).socket, packet)
                else:
                    logging.info("No route is possible, returning a no route packet.")
                    if sender_address == self.mac:
                        return False
                    packet = message_encode(NetworkTypes.NO_ROUTE, self.new_sequence_nr(), self.mac, b'',
                                            dest_mac=sender_address)
                    next_hop_mac = nx.shortest_path(self.graph, self.mac, sender_address)[0]
                    self.send(self.clients.get_client_by_mac(next_hop_mac).socket, packet)

    def exit_network(self):
        """
        Exit the current network.
        """
        pass

    def handle_join_response(self, sender_sock, sender_mac, data):
        """
        Handles a message as a join response network type. Severs the connection
        if the request was denied(empty data) or syncs own network nodes with
        the data if the request was accepted.

        :param sender_mac: The mac of the sender
        :param data: The data of the message(empty or list of mac addresses)
        :return:
        """
        client = self.clients.get_client_by_mac(sender_mac)
        logging.info("Received login request response.".format(client.mac))

        if data is None:
            logging.info("Removing client data as no data was sent.")
            self.clients.remove_client(self.clients.get_client_by_mac(sender_mac))
            return

        mac_nodes_list = pickle.loads(data)
        logging.info("Received JOIN RESPONSE with mac_nodes_list: {}".format(mac_nodes_list))
        for mac_node in mac_nodes_list:
            if mac_node.mac not in self.clients.get_client_macs():
                self.clients.add_client(mac_node)
        self.clients.add_client(Client(sender_mac, sender_sock))
        self.queue.put((NetworkTypes.JOIN_INFO, ("BlueNode", sender_mac)))

    def handle_join_request(self, sender_mac):
        """
        Handles a message as a join request message. Accepts or denies a join
        request based on the total network size. Sends empty message with the
        packet if the request has been denied or a list of mac address of the
        network if it has been accepted. Also broadcast a join info message to
        the rest of the network if the node has been accepted.

        :param sender_mac: The mac of the sender
        """
        client = self.clients.get_client_by_mac(sender_mac)

        # The client may not join the network if it is full.
        if self.clients.get_client_amount() >= 10:
            self.clients.remove_client(client)
            packet = message_encode(
                NetworkTypes.NETWORK_JOIN_RESPONSE,
                self.new_sequence_nr(),
                self.mac,
                b'')
            logging.debug("Sending join denied packet to [%s]", sender_mac)
            self.send(client.sock, packet)
        # The client may join this network.
        else:
            # Remove socket information and the sender mac client information.
            mac_data_list = [
                Client(client.mac, None) for
                client in self.clients.get_clients()
                if client.mac != sender_mac.upper()
            ]

            if self.topology_detection_method == TopologyDetectionMethod.on_change:
                with self.graph_lock:
                    self.graph.add_edge(self.mac, sender_mac)
            print([a.mac for a in mac_data_list])

            # Tell the node he may join the network.
            packet = message_encode(
                NetworkTypes.NETWORK_JOIN_RESPONSE,
                self.new_sequence_nr(),
                self.mac,
                pickle.dumps(mac_data_list)
            )
            logging.debug("Sending JOIN_RESPONSE (allowed) to {}".format(sender_mac))
            self.send(client.socket, packet)
            logging.debug("Done")

            # if self.topology_detection_method == TopologyDetectionMethod.heartbeat:
            # Announce new node in the network.
            logging.info("Sending ANNOUNCE_NODE for newly connected node: {}".format(client.mac))
            packet = message_encode(
                NetworkTypes.ANNOUNCE_NODE,
                self.new_sequence_nr(),
                self.mac,
                client.mac.encode()
            )

            self.send_broadcast(packet)

            if self.topology_detection_method == TopologyDetectionMethod.on_change:
                logging.debug("Sending topology to joining node.")
                self.share_topology(NetworkTypes.SEND_TOP_TO_JOINING_NODE, client.socket)
                logging.debug("Done")
                # Send topology to joining node

            logging.debug("A new client joined this node.\nConnected clients: {}\nTopology: {}".format([x.mac for x in self.clients.get_connected_clients()], self.graph.edges()))

    def handle_announce_node(self, sender_sock, packet, data):
        """
        Handles a message as an announce node network type. Tries to latch
        to the newly joined node if it's possible. Also broadcast the announcement
        message further to the other connected nodes.

        :param sender_sock: The socket of the sender
        :param packet: The packet of the message
        :param data: The data of the packet(mac address of the new node)
        """
        mac_addr = data.decode()
        logging.info("ANNOUNCE_NODE for {}\nClients in network: {}".format(mac_addr, self.clients.get_client_macs()))
        if mac_addr not in self.clients.get_client_macs() and mac_addr != self.mac:
            logging.info("Added node")
            self.clients.add_client(Client(mac_addr, None))

        # Try to connect to this node if you don't have enough connections yet.
        # if len(self.clients.get_client_sockets()) < 10:
        #     self.latch_node(mac_addr, 1)
        logging.info("Sending ANNOUNCE_NODE to {}".format([x.getsockname() for x in self.clients.get_client_sockets() if x != sender_sock.getsockname()]))
        self.send_broadcast(packet, sender_sock)

    def handle_broadcast(self, msg_type, sender_sock, packet, sender_mac, message):
        """
        Handles a message as a broadcast message. Broadcasts the message to all
        other connected nodes except for the sender of the broadcast message.
        Also puts the message in the data queue.

        :param msg_type: Type of the broadcast message
        :param sender_sock: The socket of the sender
        :param packet: The packet of the message
        :param sender_mac: The mac of the sender
        :param message: The message of the packet
        """
        logging.info("Received broadcast message from [%s]" % sender_mac)
        self.send_broadcast(packet, sender_sock)
        self.queue.put((NetworkTypes.BROADCAST_MESSAGE, (sender_mac, message)))

    def handle_direct(self, sender_sock, packet, sender_mac, dest_mac, message):
        """
        Handles a message as a direct message. Puts the message of the packet
        in the queue if the destination of the mac address is the current mac
        address. If not, it will direct the packet further to its destination.

        :param sender_sock: The socket of the sending client
        :param packet: The packet of the message
        :param sender_mac: The mac of the sender
        :param dest_mac: The mac of the destination
        :param message: The message of the packet
        """
        if dest_mac == self.mac:
            self.queue.put((NetworkTypes.DIRECT_MESSAGE, (sender_mac, message)))
            logging.info("Message for myself")
        else:
            logging.info("Routing")
            self.route_direct(sender_mac, dest_mac, packet, sender_sock)

    def handle_exist(self, sender_sock, packet, sender_mac):
        """
        Handles a message as an exist message. Updates the heartbeat network
        dictionary with a new or existing dict object with it's timestamp. Also
        broadcast the message further.

        :param sender_sock: The socket of the sender
        :param packet: The packet of the message
        :param sender_mac: The mac of the sender
        """
        self.heartbeat_network[sender_mac] = datetime.now()
        self.send_broadcast(packet, sender_sock)

    def handle_message(self, sock, packet):
        """
        Handles a message differently according to its message type.

        :param sock: The socket with the packet
        :param packet: The packet of the message
        """
        msg_type, sender_mac, dest_mac, msg_sequence, _, data = message_decode(packet)
        logging.info("Received msg with type: {}".format(msg_type))
        sender_mac = sender_mac.upper()
        dest_mac = dest_mac.upper()

        if sender_mac == self.mac:
            return

        client = self.clients.get_client_by_mac(sender_mac)

        if client is None:
            logging.debug("Message received from unknown sender [%s]" % sender_mac)
            return

        if msg_type != NetworkTypes.NETWORK_JOIN_RESPONSE and not client.check_valid_message_id(msg_sequence):
            return

        if msg_type == NetworkTypes.NETWORK_JOIN_RESPONSE:
            self.handle_join_response(sock, sender_mac, data)

        if msg_type == NetworkTypes.NETWORK_JOIN_REQUEST:
            self.handle_join_request(sender_mac)

        if msg_type == NetworkTypes.ANNOUNCE_NODE:
            self.handle_announce_node(sock, packet, data)

        if msg_type == NetworkTypes.BROADCAST_MESSAGE:
            self.handle_broadcast(msg_type, sock, packet, sender_mac, data)

        if msg_type == NetworkTypes.DIRECT_MESSAGE:
            logging.debug("Received direct message from {}".format(sender_mac))
            self.handle_direct(sock, packet, sender_mac, dest_mac, data)

        if msg_type == NetworkTypes.EXIST:
            self.handle_exist(sock, packet, sender_mac)

        if msg_type == NetworkTypes.SEND_TOP_TO_JOINING_NODE:
            logging.info("Sending topology to joining node...")
            self.handle_topology_change(pickle.loads(data))
            self.share_topology(NetworkTypes.SEND_TOP_TO_JOINED_NODE, client.socket)

        if msg_type == NetworkTypes.SEND_TOP_TO_JOINED_NODE:
            logging.info("Received topology from joined node, share TOP_UPDATE")
            self.handle_topology_change(pickle.loads(data))
            self.connecting = False
            self.share_topology(NetworkTypes.TOP_UPDATE)

        if msg_type == NetworkTypes.TOP_UPDATE:
            self.handle_topology_change(pickle.loads(data))
            self.send_broadcast(packet, client.socket)

        if msg_type == NetworkTypes.NODE_DISCONNECTED:
            with self.graph_lock:
                if self.graph.has_node(data.decode()):
                    self.graph.remove_node(data.decode())
                    self.clients.remove_client(self.clients.get_client_by_mac(data.decode()))
            logging.debug("Topology: {}".format(self.graph.edges()))
            self.send_broadcast(packet, client.socket)

        if msg_type == NetworkTypes.NO_ROUTE:
            logging.debug("Earlier sent direct message couldn't reach destination.")

    def handle_clients(self):
        logging.info("Waiting for incoming data...")
        while True:
            to_be_read, _, _ = select.select(self.clients.get_client_sockets(), [], [], 1)
            for sock in to_be_read:
                self.status = "processing"

                packets = self.recv(sock)

                for packet in packets:
                    self.handle_message(sock, packet)

            self.status = "idle"

    def handle_topology_change(self, topology: nx.Graph):
        """
        Merges the received topology with the local topology. Furthermore updates the list of clients.

        :param topology: The topology to be merged with the local topology.
        :return: None
        """
        with self.graph_lock:
            self.graph = nx.compose(self.graph, topology)
            for node in self.graph.nodes():
                self.clients.add_client(Client(node, None))
        logging.debug("Topology: {}".format(self.graph.edges()))
        logging.debug("Directly connected nodes: {}".format([x.mac for x in self.clients.get_connected_clients()]))

    def share_topology(self, network_type: NetworkTypes, sock: BluetoothSocket=None):
        """
        Broadcasts or directly sends the local Networkx toplogy with a certain network type.
        :param network_type: Network type of the packet containing the local topology.
        :param sock: If defined the single destination of the packet containing the topology.
        :return: None
        """
        with self.graph_lock:
            packet = message_encode(
                network_type,
                self.new_sequence_nr(),
                self.mac,
                pickle.dumps(self.graph)
            )

        if sock is None:
            self.send_broadcast(packet)
        else:
            self.send(sock, packet)

    def send_packet(self, network_type: NetworkTypes, sock: BluetoothSocket=None, data: bytes=b'', skip_sock: BluetoothSocket=""):
        """
        Sends a packet. When sock is empty this is broadcasted else it's sent only to this socket.

        :param network_type: The type of the packet.
        :param sock: If defined the single destination of this packet.
        :param data: If defined the data to be sent else empty byte array.
        :param skip_sock: If sock is not defined this can indicate the socket to be skipped in broadcasting.
        :return: None
        """
        packet = message_encode(
            network_type,
            self.new_sequence_nr(),
            self.mac,
            data
        )

        if sock is None:
            self.send_broadcast(packet, skip_sock)
        else:
            self.send(sock, packet)

    def new_sequence_nr(self) -> int:
        """
        Increments the sequence number for validating packets.

        :return: int: message sequence number
        """
        if self.sequence_number == MAX_INT:
            self.sequence_number = 0
        else:
            self.sequence_number += 1
        return self.sequence_number
