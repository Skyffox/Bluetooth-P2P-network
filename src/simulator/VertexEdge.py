# Taken from https://github.com/npanov/simple-qt5-graph-editor
from array import array
import reprlib
import doctest
import functools
import operator
import math
import numbers
import random

class Vertex:
    """
    Multidimensional vertex class

    Built from an iterable of numbers:

        >>> Vertex([1, 2])
        Vertex([1.0, 2.0])
        >>> Vertex((1, 2, 3.5))
        Vertex([1.0, 2.0, 3.5])

        >>> v1 = Vertex([1, 10, 25.25])
        >>> x, y, z = v1
        >>> x, y, z
        (1.0, 10.0, 25.25)
        >>> v1
        Vertex([1.0, 10.0, 25.25])
        >>> v1_clone = eval(repr(v1))
        >>> v1 == v1_clone
        True

        >>> str(v1_clone)
        '(1.0, 10.0, 25.25)'

        >>> v1.x
        1.0
        >>> v1.x == v1[0]
        True
        >>> v1.z
        Traceback (most recent call last):
        ...
        AttributeError: Vertex has no attribute z

        >>> v1.y = 4.44
        >>> v1.y
        4.44

        >>> v1.z = 100
        Traceback (most recent call last):
        ...
        AttributeError: Attribute name z not allowed for class Vertex

    """
    free_ports = list(range(1, 31))
    shortcut_names = 'xy'

    def rand_adress(self):
        # From https://gist.github.com/pklaus/9638536
        a = "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
            )
        return a.upper()

    def __init__(self, components, capture=True):
        self._components = array('d', components)

        if len(Vertex.free_ports) == 0:
            print("Warning no ports left!")
        elif not capture:
            self.port = Vertex.free_ports[0]
            self.adress = self.rand_adress()
            self.name = chr(48 + self.port)
            print((self.port, self.adress, self.name))
            del Vertex.free_ports[0]

    def next_port(self):
        self.port = Vertex.free_ports[0]
        del Vertex.free_ports[0]

    def __iter__(self):
        return iter(self._components)


    def __repr__(self):
        cls = type(self)
        components = reprlib.repr(self._components)
        components = components[components.find('['):-1]
        return '{.__name__}({} {})'.format(cls, self.name, components)


    def __str__(self):
        return str(tuple(self))


    def __eq__(self, other):
        return len(self) == len(other) and all(a == b for a,b in zip(self, other))


    def __abs__(self):
        return math.sqrt(sum(x * x for x in self))


    def __len__(self):
        return len(self._components)


    def __bool__(self):
        return bool(abs(self))


    def __getitem__(self, index):
        cls = type(self)
        if isinstance(index, slice):
            return cls(self._components[index])
        elif isinstance(index, numbers.Integral):
            return self._components[index]
        else:
            msg = '{.__name__} indices must be integers'
            raise TypeError(msg.format(cls))


    def __getattr__(self, name):
        cls = type(self)
        if len(name) == 1:
            pos = cls.shortcut_names.find(name)
            if 0 <= pos < len(self._components):
                return self._components[pos]

        msg = '{.__name__} has no attribute {}'
        raise AttributeError(msg.format(cls, name))


    def __setattr__(self, name, value):
        cls = type(self)
        if len(name) == 1:
            pos = cls.shortcut_names.find(name)
            if 0 <= pos < len(self._components):
                self._components[pos] = value
            else:
                msg = 'Attribute name {} not allowed for class {.__name__}'
                raise AttributeError(msg.format(name, cls))
        else:
            super().__setattr__(name, value) # TODO: needs patching + __setitem__

class VertexTautologyError(Exception):
    """Exception raised for attempt to build an edge between two vertices that are the same.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


class Edge:
    """
    Edge class

    >>> v1 = Vertex([1, 2])
    >>> v2 = Vertex([4, 4])
    >>> v3 = Vertex([3, 1])
    >>> e1 = Edge(v1, v2)
    >>> e1
    Edge(Vertex([1.0, 2.0]), Vertex([4.0, 4.0]))
    >>> e2 = Edge(v2, v3, oriented=True)
    >>> e2
    Edge(Vertex([4.0, 4.0]), Vertex([3.0, 1.0]), oriented=True)

    >>> Edge((1,2), Vertex([4.0, 4.0]))
    Traceback (most recent call last):
    ...
    TypeError: Edge() argument must be Vertex

    >>> e2.v1, e2.v2 = e2.v2, e2.v1
    >>> e2
    Edge(Vertex([3.0, 1.0]), Vertex([4.0, 4.0]), oriented=True)

    >>> e2_clone = eval(repr(e2))
    >>> e2_clone == e2
    True

    >>> v1_clone = Vertex(v1)
    >>> v1 == v1_clone
    True

    >>> Edge(v1, v1_clone)
    Traceback (most recent call last):
    ...
    VertexTautologyError: Can't edge same vertex

    >>> abs(e1)
    3.605551275463989

    """
    identifier = 0

    def __init__(self, v1, v2, oriented=False):
        if v1 == v2:
            raise VertexTautologyError('Can\'t edge same vertex')
        self.v1 = v1
        self.v2 = v2
        self.oriented = bool(oriented)


    def __repr__(self):
        cls = type(self)
        oriented = ''
        if self.oriented:
            oriented = ', oriented=True'
        return '{.__name__}({}, {}{})'.format(cls, repr(self._v1), repr(self._v2), oriented)

    @property
    def v1(self):
        return self._v1


    @v1.setter
    def v1(self, value):
        cls = type(self)
        if isinstance(value, Vertex):
            self._v1 = value
        else:
            msg = '{.__name__}() argument must be Vertex'
            raise TypeError(msg.format(cls))


    @property
    def v2(self):
        return self._v2


    @v2.setter
    def v2(self, value):
        cls = type(self)
        if isinstance(value, Vertex):
            self._v2 = value
        else:
            msg = '{.__name__}() argument must be Vertex'
            raise TypeError(msg.format(cls))


    def __eq__(self, other):
        return self.v1 == other.v1 and self.v2 == other.v2 and self.oriented == other.oriented


    def __abs__(self):
        return math.sqrt(sum((i1 - i2)**2 for i1, i2 in zip(self.v1, self.v2))) # multidimensional


if __name__ == "__main__":
    doctest.testmod()
