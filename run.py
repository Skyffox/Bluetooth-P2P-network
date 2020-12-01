import logging
import os
import signal
import threading
import sys
import time

from queue import Queue
from src.GUI.gui import MainWindow
from src.bluetooth_node.blue_node import BlueNode
from src.handler.handler import Handler
from src.monitor.monitor import Monitor
from options import Args


def read_key_val_file(name):
    """
    Reads a file containing key value pairs separated by an = as dictionary
    containing strings.
    """
    settings = {}

    with open(name, "r") as f:
        for line in f:
                key, val = line[:-1].split("=")
                settings[key] = val

    return settings


def setup_dirs():
    dirs = ["logs", "data"]

    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)


def main():
    setup_dirs()

    # Create a logger.
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
        handlers=[
            logging.FileHandler("logs/error.log"),
            logging.StreamHandler()
        ]
    )

    settings = read_key_val_file("settings.cfg")

    logging.debug("sys.argv: {}".format(sys.argv))

    if len(sys.argv) == 4:
        mac, _, port = sys.argv[Args.simulation].split('+')[0].split('-')
        title = mac + " at " + port
        settings["baddr"] = mac
    else:
        title = "A simple chat"

    logging.info("Settings: {}".format(settings))

    run_monitoring = bool(int(settings["monitoring"]))

    if not run_monitoring and bool(int(sys.argv[Args.monitoring])):
        run_monitoring = True

    # Create queues for data to be send to and read from.
    data_queue = Queue()
    input_gui_queue = Queue()
    output_gui_queue = Queue()

    node = BlueNode(settings["server_uuid"], data_queue, settings["baddr"])
    window = MainWindow(input_gui_queue, output_gui_queue, title)

    handler = Handler(data_queue, input_gui_queue, output_gui_queue, node, settings["baddr"])

    # Start first thread for Bluetooth nodes.
    thread = threading.Thread(target=node.run, name="BlueNode")
    thread.daemon = True
    thread.start()

    logging.info("Started BlueNode")

    # Start second thread for the handler.
    handler_thread = threading.Thread(target=handler.run, name="Handler")
    handler_thread.daemon = True
    handler_thread.start()

    logging.info("Starting Handler Queue")

    # Oh no...
    global monitor
    monitor = None
    if run_monitoring:
        monitor = Monitor(settings["monitoring_ip"], int(settings["monitoring_port"]), settings["baddr"], node)

        # Start interface in thread
        monitor_thread = threading.Thread(target=monitor.run, name="Monitor")
        monitor_thread.daemon = True
        monitor_thread.start()

    logging.info("Starting GUI")

    signal.signal(signal.SIGTERM, close_gracefully)

    window.run()
    monitor.running = False


def close_gracefully(signal, stacktrace):
    global monitor
    monitor.running = False
    # Give the monitor enough time to write to file.
    time.sleep(1)
    exit()


if __name__ == "__main__":
    print("sys.argv len: {}".format(sys.argv))
    if len(sys.argv) < 3:
        print(open("failure", "r").read())
    else:
        main()
