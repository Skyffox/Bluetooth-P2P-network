import signal
import socket
import sys
import time
from typing import Tuple, Dict, List

RFCOMM = 3
PORT_ANY = 0


class BluetoothError(IOError):
    pass


def setup_simulation(arg):
    """
    Sets the server port to be used in the simulated Bluetooth socket class as well as all neighboring nodes. This is
    done based upon arg which contains the Bluetooth, port of this device and all neighboring nodes.

    :param arg: System arguments
    :return: None
    """
    print("Arg: {}".format(arg))
    devices = arg.split("+")
    BluetoothSocket.on = True
    BluetoothSocket.my_mac, _, my_port = devices[0].split("-")
    BluetoothSocket.my_server_port = int(my_port)

    # Set window title
    print("\33]0;{} at {}\a".format(BluetoothSocket.my_mac, BluetoothSocket.my_server_port), end='')
    sys.stdout.flush()

    for i in range(1, len(devices)):
        neighbor_mac, neighbor_name, neighbor_port = devices[i].split('-')
        BluetoothSocket.neighbor_nodes.append({"host": neighbor_mac, "name": neighbor_name, "port": int(neighbor_port)})


class BluetoothSocket:
    """
    Emulates a Bluetooth socket with a TCP socket. Only one instance of a server port is allowed. This server port
    can listen and accept connections.
    """
    my_server_port = 0
    my_server_sock = None  # type: BluetoothSocket
    neighbor_nodes = []  # type: List[Dict[str: any]]
    my_mac = ""
    on = False

    def __init__(self, connection_type: int, sock=None):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

        self.listen = self.sock.listen
        # The send function from the underlying TCP socket is used instead of the emulated send function as the
        # simulated function is to slow for the Heartbeat network maintenance algorithm.
        self.send = self.sock.send
        self.close = self.sock.close
        self.fileno = self.sock.fileno
        self.received = b''

    @staticmethod
    def neighbor_exists(mac: str):
        """
        Checks if the Bluetooth address of a node is nearby according to the earlier set neighbors list.

        :param mac: Bluetooth address of a node.
        :return: True if the Bluetooth address corresponds to a neighbor.
        """
        for neighbor in BluetoothSocket.neighbor_nodes:
            if neighbor['host'] == mac:
                return True
        return False

    def getsockname(self):
        _, port = self.sock.getsockname()
        return self.my_mac, port

    def connect(self, virt_adress: Tuple[str, int]) -> None:
        """
        Connects to a node. First of all checks if this node is in the earlier set neighbor list. When something
        goes wrong a Bluetooth specific error is thrown. After connecting the virtual Bluetooth address is sent
        to the server which cannot know this in any other way.

        :param virt_adress: Virtual Bluetooth address of server node
        :return: None
        """
        if not BluetoothSocket.neighbor_exists(virt_adress[0]):
            raise BluetoothError("(112, 'Host is down')")
        try:
            self.sock.connect(('localhost', virt_adress[1]))
        except ConnectionRefusedError:
            raise BluetoothError("(111, 'Connection refused')") from None
        self.sock.send(self.my_mac.encode())

    def bind(self, virt_adress: Tuple[str, int]) -> None:
        """
        Binds a TCP socket to the earlier set server port. The Bluetooth address of the chosen interface as well
        as the port are ignored as other chat processes use the predetermined value for connecting as well.

        :param virt_adress: Bluetooth address of the interface and port to be used. This is ignored.
        :return: Noen
        """
        self.sock.bind(('localhost', BluetoothSocket.my_server_port))
        BluetoothSocket.my_server_port = self.sock

    def accept(self) -> Tuple['BluetoothSocket', Tuple[str, int]]:
        """
        Accept a connection from a client. Fetches it's virtual Bluetooth address.
        :return: BluetoothSocket, (virtual Bluetooth address of client, port of client)
        """
        client_sock, client_info = self.sock.accept()
        virtual_mac = client_sock.recv(17).decode()
        return BluetoothSocket(PORT_ANY, sock=client_sock), (virtual_mac, client_info[1])

    def realistic_send(self, data: bytes, flags: int = 0) -> int:
        """
        Sends data across a Bluetooth socket. Bluetooth sockets fail immediatly when the corresponding connection
        is broken and an attempt is made to send. TCP sockets do something similar only for receival. Therefore
        one byte is received before sending and when this goes wrong the corresponding Bluetooth error is thrown.
        This byte is appended to a internal buffer as it might be data for a future recv.
        """
        # print("Sending data: {}".format(data))
        self.sock.settimeout(0.25)

        try:
            received = self.sock.recv(1)
        except socket.timeout:
            self.sock.settimeout(None)
            return self.sock.send(data, flags)

        if len(received) == 0:
            raise BluetoothError("(104, 'Connection reset by peer')")
        else:
            self.received += received

        self.sock.settimeout(None)

        return self.sock.send(data, flags)

    def recv(self, buflen: int, flags: int = 0) -> bytes:
        """
        Receives data from a socket and might append earlier received data by the connection alive test in the
        send function.
        """
        out = self.sock.recv(buflen, flags)

        if len(out) == 0:
            raise BluetoothError("(104, 'Connection reset by peer')")

        if len(self.received) != 0:
            out = self.received + out
            self.received = b''
        return out
