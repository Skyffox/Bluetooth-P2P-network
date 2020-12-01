"""
Create a JSON package that is send to the AdHoc Monitor Tool.
"""

import os
import signal
import socket
import json
import time
from datetime import datetime

import psutil as psutil

from src.bluetooth_node.blue_node import BlueNode


class Monitor:
    def __init__(self, monitor_ip: str, monitor_port: int, mac: str, blue_node: BlueNode):
        self.monitor_addr = (monitor_ip, monitor_port)

        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM)

        self.mac = mac
        self.blue_node = blue_node

        self.running = True

        self.status = None
        self.previously_total_sent = 0
        self.previously_total_received = 0

        self.timeout = 150  # Milliseconds

        self.sent_chart = {}
        self.recv_chart = {}
        self.total_chart = {}

        self.cpu_usage_chart = {}
        self.total_cpu_usage_chart = {}

        self.p = psutil.Process(os.getpid())
        self.f = open("logs/data_" + self.mac.replace(":", "") + ".txt", "w")

    def run(self):
        while self.running:
            self.log_data()
            self.send_data()
            time.sleep(self.timeout / 1000)
        self.f.close()
        exit()

    def log_data(self):
        sent = self.blue_node.total_sent_bytes
        recvd = self.blue_node.total_received_bytes
        tot = sent+recvd
        t = round(time_millis() / self.timeout)
        self.f.write(str(t) + " " + str(sent) + " " + str(recvd) + " " + str(tot) + "\n")

    def send_data(self):
        """
        Create a JSON package and send this to the Android module.
        """
        data = {}

        millis = time_millis()

        data["address"] = self.mac.upper()
        data["status"] = self.blue_node.status
        data["timeStamp"] = millis
        self.recv_chart[millis] = (self.blue_node.total_received_bytes - self.previously_total_received) / self.timeout
        self.sent_chart[millis] = (self.blue_node.total_sent_bytes - self.previously_total_sent) / self.timeout
        self.total_chart[millis] = self.recv_chart[millis] + self.sent_chart[millis]
        self.total_cpu_usage_chart[millis] = psutil.cpu_percent()

        self.cpu_usage_chart[millis] = self.p.cpu_percent() / psutil.cpu_count()

        if len(self.recv_chart) > 10:
            del self.recv_chart[min(self.recv_chart.keys())]
            del self.sent_chart[min(self.sent_chart.keys())]
            del self.total_chart[min(self.total_chart.keys())]

            del self.cpu_usage_chart[min(self.cpu_usage_chart.keys())]
            del self.total_cpu_usage_chart[min(self.total_cpu_usage_chart.keys())]

        data["ioTotalChart"] = self.total_chart
        data["ioRecvChart"] = self.recv_chart
        data["ioSendChart"] = self.sent_chart
        data["speedChart"] = self.cpu_usage_chart  
        data["cpuUsageChart"] = self.cpu_usage_chart
        data["cpuTotalUsageChart"] = self.total_cpu_usage_chart

        neighbours = []
        for client in self.blue_node.clients.get_connected_clients():
            neighbour_data = {"address": client.mac.upper(), "bytesSend": client.bytes_sent,
                              "bytesReceived": client.bytes_received, "dataSend": ""}

            neighbours.append(neighbour_data)

        data["neighbours"] = neighbours
        data["customValues"] = ""

        json_data = json.dumps({
            "type": "data",
            "node": data
        })
        self.sock.sendto(json_data.encode("utf-8"), self.monitor_addr)

        self.previously_total_sent = self.blue_node.total_sent_bytes
        self.previously_total_received = self.blue_node.total_received_bytes


def time_millis():
    return int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds() * 1000)
