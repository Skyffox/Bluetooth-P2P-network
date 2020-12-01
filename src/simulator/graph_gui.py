# Taken from https://github.com/npanov/simple-qt5-graph-editor
import os
import sys
import math
import operator
import psutil
from PyQt5.QtWidgets import QWidget, QApplication, QMainWindow, QAction, qApp, QSizePolicy, QSlider
from PyQt5.QtCore import Qt, QPoint
from PyQt5.QtGui import QPainter
from PyQt5.QtGui import QIcon
import subprocess

from VertexEdge import Vertex, Edge


class MainWindow(QMainWindow):
    MODE_VERTEX = 'V'
    MODE_VERTEX_DEL = 'D'
    MODE_EDGE = 'E'
    MODE_FIND = 'P'

    MSG_MODE_VERTEX = 'Vertex insert and move mode'
    MSG_MODE_VERTEX_DEL = 'Vertex delete mode'
    MSG_MODE_EDGE = 'Edge insert mode'
    MSG_MODE_FIND = 'Path find mode'

    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):

        self.mode = self.MODE_VERTEX

        self.setGeometry(300, 300, 500, 500)
        self.setWindowTitle('Simple graph')

        self.canvas = Canvas()
        self.setCentralWidget(self.canvas)
        path = os.path.dirname(os.path.abspath(__file__))
        exitAction = QAction(QIcon(os.path.join(path, 'exit24.png')), 'Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.triggered.connect(self.onshutdown)

        insertVertexAction = QAction(QIcon(os.path.join(path, 'vertex.png')), 'Vertex', self)
        insertVertexAction.setShortcut('Ctrl+V')
        insertVertexAction.triggered.connect(self.vertexMode)

        addEdgeAction = QAction(QIcon(os.path.join(path, 'edge.png')), 'Edge', self)
        addEdgeAction.setShortcut('Ctrl+E')
        addEdgeAction.triggered.connect(self.edgeMode)

        startNodesAction = QAction(QIcon(os.path.join(path, 'start.png')), 'Start', self)
        startNodesAction.triggered.connect(self.start_nodes)

        deleteVertexAction = QAction(QIcon(os.path.join(path, 'delete.png')), 'Delete', self)
        deleteVertexAction.setShortcut('Ctrl+D')
        deleteVertexAction.triggered.connect(self.deleteMode)

        stopAction = QAction(QIcon(os.path.join(path, 'stop.png')), 'Delete', self)
        stopAction.setShortcut('Ctrl+S')
        stopAction.triggered.connect(self.kill_processes)

        findPathAction = QAction(QIcon(os.path.join(path, 'find.png')), 'Path', self)
        findPathAction.setShortcut('Ctrl+P')
        findPathAction.triggered.connect(self.findMode)

        self.statusBar()
        self.statusBar().showMessage(self.MSG_MODE_VERTEX)

        self.toolbar = self.addToolBar('Simple graph')

        self.toolbar.addAction(insertVertexAction)
        self.toolbar.addAction(addEdgeAction)
        self.toolbar.addAction(deleteVertexAction)
        self.toolbar.addAction(findPathAction)

        sld = QSlider(Qt.Horizontal)
        sld.valueChanged.connect(self.vertexResize)
        sld.setMinimum(1)
        sld.setMaximum(15)

        self.toolbar.addWidget(sld)
        self.toolbar.addAction(startNodesAction)
        self.toolbar.addAction(stopAction)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.toolbar.addWidget(spacer)
        self.toolbar.addAction(exitAction)

        self.show()

    def kill_processes(self):
        for proc in psutil.process_iter():
            # print(proc.cmdline())
            if "make run-simulation" in " ".join(proc.cmdline()):
                proc = proc.children()[0].children()[0]
                print("PID to be terminated: {}".format(proc.pid))
                proc.terminate()

    def onshutdown(self):
        self.kill_processes()
        qApp.quit()

    def start_nodes(self):
        edges = [elem for sublist in list(self.canvas.edges.values()) for elem in sublist]
        print("EDGES: {}".format(edges))
        print("VERTICES: {}".format(self.canvas.vertices))

        for vertex in self.canvas.vertices:
            args = []
            args.append(vertex.adress + "-" + vertex.name + "-" + str(vertex.port + 49129))
            for edge in edges:
                if vertex == edge.v1:
                    v = edge.v2
                elif vertex == edge.v2:
                    v = edge.v1
                if vertex == edge.v1 or vertex == edge.v2:
                    args.append("{}-{}-{}".format(v.adress, v.name, v.port + 49129))

            print('gnome-terminal --command="make run-simulation MON={} ARG={} SIM={}"'.format(sys.argv[1], sys.argv[2], "+".join(args)))
            os.system('gnome-terminal --command="make run-simulation MON={} ARG={} SIM={}"'.format(sys.argv[1], sys.argv[2], "+".join(args)))

    def vertexResize(self, value):
        self.canvas.point_radius = value
        self.canvas.update()

    def vertexMode(self):
        self.canvas.mode = self.MODE_VERTEX
        self.selected_vertex_idx = None
        self.draggin_idx = []
        self.statusBar().showMessage(self.MSG_MODE_VERTEX)

    def deleteMode(self):
        self.canvas.mode = self.MODE_VERTEX_DEL
        self.selected_vertex_idx = None
        self.draggin_idx = []
        self.statusBar().showMessage(self.MSG_MODE_VERTEX_DEL)

    def edgeMode(self):
        self.canvas.mode = self.MODE_EDGE
        self.selected_vertex_idx = None
        self.draggin_idx = []
        self.statusBar().showMessage(self.MSG_MODE_EDGE)

    def findMode(self):
        self.canvas.mode = self.MODE_FIND
        self.selected_vertex_idx = None
        self.draggin_idx = []
        self.statusBar().showMessage(self.MSG_MODE_FIND)


class Canvas(QWidget):
    point_radius = 3
    DELTA = 3

    def __init__(self, parent=None):
        super().__init__()

        self.setGeometry(0, 0, 400, 400)
        self.vertices = []
        self.edges = {}
        self.draggin_idx = []
        self.selected_vertex_idx = None
        self.mode = MainWindow.MODE_VERTEX
        self.cotrolPressed = False

    def paintEvent(self, e):
        qp = QPainter()
        qp.begin(self)
        self.drawGraph(qp)
        qp.end()

    def drawGraph(self, qp):
        qp.setPen(Qt.black)
        qp.setBrush(Qt.black)

        for i, vertex in enumerate(self.vertices):

            qpoint = QPoint(vertex.x, vertex.y)

            if i == self.selected_vertex_idx: 
                qp.setBrush(Qt.red)
            elif i in self.draggin_idx:
                qp.setBrush(Qt.blue)

            qp.drawEllipse(qpoint, self.point_radius * 2, self.point_radius * 2)

            qp.setBrush(Qt.black)

        for _, edges in self.edges.items():
            for edge in edges:
                qp.drawLine(edge.v1.x, edge.v1.y, edge.v2.x, edge.v2.y)

    def _get_point(self, evt):
        return evt.pos().x(), evt.pos().y()

    def _capture_vertex(self, x, y):
        vertex = Vertex([x, y])
        distances = []
        for v in self.vertices:
            distances.append(math.sqrt(sum((i1 - i2) ** 2 for i1, i2 in zip(v, vertex))))
        if distances and (min(distances) < self.point_radius + self.DELTA):
            captured_vertex_idx, _ = min(enumerate(distances), key=operator.itemgetter(1))
            return captured_vertex_idx
        return None

    def addVertex(self, x, y):
        new_vertex = Vertex([x, y], False)
        self.vertices.append(new_vertex)
        self.edges[id(new_vertex)] = []

        return

    def deleteVertex(self, vertex_idx):
        vertex = self.vertices[vertex_idx]
        print(vertex)
        for vertex_id, edges in self.edges.items():
            for i, edge in enumerate(edges):
                print("Incoming edges:")
                print(edge)
                if edge.v2 == vertex:
                    print("Deleting {}".format(edge))
                    del edges[i]
        print("Deleting outgoing edges")
        del self.edges[id(vertex)]
        print("Deleting vertex")
        del self.vertices[vertex_idx]
        Vertex.free_ports.append(vertex.port)

    def addEdge(self, v1_idx, v2_idx, directed=False):
        v1 = self.vertices[v1_idx]
        v2 = self.vertices[v2_idx]
        new_edge = Edge(v1, v2, directed)
        new_edge_backwards = Edge(v2, v1, directed)
        if not new_edge in self.edges[id(v1)] and not new_edge_backwards in self.edges[id(v2)]:
            self.edges[id(v1)].append(new_edge)

        return

    def grabVertex(self, vertex_idx):
        modifiers = QApplication.keyboardModifiers()
        if modifiers == Qt.ControlModifier:

            print('Control+Click')
            if vertex_idx not in self.draggin_idx:
                self.draggin_idx.append(vertex_idx)
            else:
                self.draggin_idx.remove(vertex_idx)

            self.cotrolPressed = True
            self.update()

        else:
            if self.cotrolPressed == True:
                if vertex_idx not in self.draggin_idx:
                    self.draggin_idx.append(vertex_idx)
                else:
                    self.draggin_idx.remove(vertex_idx)
                    self.draggin_idx.append(
                        vertex_idx)  # Making sure the pointed vertex is the last in the indices list
                self.cotrolPressed = False
            else:
                self.draggin_idx = [vertex_idx, ]

        print("$" * 50)
        print(self.draggin_idx)
        return

    def mousePressEvent(self, evt):

        if self.mode == MainWindow.MODE_VERTEX:

            if evt.button() == Qt.LeftButton:
                x, y = self._get_point(evt)
                captured_vertex_idx = self._capture_vertex(x, y)
                print(captured_vertex_idx)
                if not captured_vertex_idx is None:
                    self.grabVertex(captured_vertex_idx)
                else:
                    self.addVertex(x, y)
                    self.update()

        elif self.mode == MainWindow.MODE_EDGE:

            if evt.button() == Qt.LeftButton and self.draggin_idx == []:
                x, y = self._get_point(evt)
                captured_vertex_idx = self._capture_vertex(x, y)
                if not captured_vertex_idx is None:
                    if self.selected_vertex_idx is None:
                        self.selected_vertex_idx = captured_vertex_idx
                        self.update()
                    else:
                        if self.selected_vertex_idx == captured_vertex_idx:  # Same vertex, deselect
                            self.selected_vertex_idx = None
                            self.update()
                        else:
                            self.addEdge(self.selected_vertex_idx, captured_vertex_idx)
                            self.selected_vertex_idx = None
                            self.update()

        elif self.mode == MainWindow.MODE_VERTEX_DEL:
            if evt.button() == Qt.LeftButton and self.draggin_idx == []:
                x, y = self._get_point(evt)
                captured_vertex_idx = self._capture_vertex(x, y)

                if not captured_vertex_idx is None:
                    self.deleteVertex(captured_vertex_idx)

                self.update()

        elif self.mode == MainWindow.MODE_FIND:
            if evt.button() == Qt.LeftButton and self.draggin_idx == []:
                x, y = self._get_point(evt)
                captured_vertex_idx = self._capture_vertex(x, y)
                if not captured_vertex_idx is None:
                    if self.selected_vertex_idx is None:
                        self.selected_vertex_idx = captured_vertex_idx
                        self.update()
                    else:
                        if self.selected_vertex_idx == captured_vertex_idx:  # Same vertex, deselect
                            self.selected_vertex_idx = None
                            self.update()
                        else:
                            distances, chain = self.dijkstra(self.selected_vertex_idx)
                            print("#" * 30, " Dijkstra result ", "#" * 30)
                            print(distances, chain)
                            self.selected_vertex_idx = None
                            self.update()

    def mouseMoveEvent(self, evt):
        if self.draggin_idx != [] and not self.cotrolPressed:

            print(self.vertices)
            print(self.edges)
            print(self.draggin_idx)

            moving_vertices = [self.vertices[i] for i in self.draggin_idx]
            last_vertex = moving_vertices[-1]

            x, y = self._get_point(evt)

            x_delta = x - last_vertex.x
            y_delta = y - last_vertex.y

            for vertex in moving_vertices:
                vertex.x += x_delta
                vertex.y += y_delta

            self.update()

    def mouseReleaseEvent(self, evt):
        if evt.button() == Qt.LeftButton and self.draggin_idx != [] and not self.cotrolPressed:

            print('*' * 40)
            print(self.vertices)
            print(self.edges)
            print(self.draggin_idx)

            moving_vertices = [self.vertices[i] for i in self.draggin_idx]
            last_vertex = moving_vertices[-1]

            x, y = self._get_point(evt)

            x_delta = x - last_vertex.x
            y_delta = y - last_vertex.y

            for vertex in moving_vertices:
                vertex.x += x_delta
                vertex.y += y_delta

            self.draggin_idx = []
            self.update()

    def dijkstra(self, v1_idx, directed=True):

        v1 = self.vertices[v1_idx]

        dist = {}
        prev = {}
        q = {}
        visited = set()

        for v in self.vertices:
            dist[id(v)] = 999999999
            prev[id(v)] = -1
            q[id(v)] = v

        print(self.edges)
        print(v1)
        print(q)

        dist[id(v1)] = 0

        while len(visited) != len(q):

            print('visited')
            print(visited)

            temp_dict = {}
            for k, v in dist.items():
                if k not in visited:
                    temp_dict[k] = v
            i = min(temp_dict, key=temp_dict.get)

            print(i)
            visited.add(i)

            v = q[i]
            print('Visiting {0!r}'.format(v))

            for e in self.edges[i]:
                if id(e.v2) in q and id(e.v2) not in visited:
                    alt = dist[i] + abs(e)
                    if alt < dist[id(e.v2)]:
                        dist[id(e.v2)] = alt
                        prev[id(e.v2)] = id(i)

            print("*" * 50)

        return dist, prev


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(open("failure", "r").read())
    else:
        app = QApplication(sys.argv)
        ex = MainWindow()
        sys.exit(app.exec_())
