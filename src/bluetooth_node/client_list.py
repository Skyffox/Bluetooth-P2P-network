from socket import socket
from typing import List, Optional

from src.bluetooth_node.client import Client


class ClientList:
    def __init__(self):
        self._clients = []

    def add_client(self, client: Client) -> None:
        client.mac = client.mac.upper()

        if self.get_client_by_mac(client.mac.upper()) is None:
            self._clients.append(client)

    def remove_client(self, client: Client) -> None:
        self._clients.remove(client)

    def get_connected_clients(self) -> List[Client]:
        """
        :return: The list of all directly connected clients.
        """
        result = []
        for client in self._clients:
            if client.socket is not None:
                result.append(client)
        return result

    def get_clients(self) -> List[Client]:
        """
        :return: The list of all clients.
        """
        return self._clients

    def get_client_by_mac(self, mac: str) -> Optional[Client]:
        """
        Returns the client object with the given mac address

        :param mac: The mac address for which you want to client object
        :returns: The paired client object or None
        """
        return next(filter(lambda client: client.mac == mac.upper(), self._clients), None)

    def get_client_by_sock(self, sock: socket) -> Optional[Client]:
        """
        Returns the client object with the given mac address

        :param sock: The socket for which you want to client object
        :returns: The paired client object or None
        """
        return next(filter(lambda client: client.socket == sock, self._clients), None)

    def get_client_macs(self) -> List[str]:
        """
        :return: A list of all mac addresses in the network
        """
        return [client.mac for client in self._clients]

    def get_client_sockets(self) -> List[socket]:
        """
        :return: A list of all connected sockets
        """
        return [client.socket for client in self._clients if client.socket is not None]

    def get_client_amount(self) -> int:
        """
        :return: How many clients are in this list
        """
        return len(self._clients)
