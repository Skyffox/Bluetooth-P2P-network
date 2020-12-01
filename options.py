"""
Decide what options to run the application with.
"""

class Monitoring:
    off = 0
    on = 1


class TopologyDetectionMethod:
    on_change = 0
    heartbeat = 1


class BroadcastMethod:
    normal = 0
    optimized = 1


class RoutingMethod:
    broadcast = 0
    direct = 1


class Args:
    monitoring = 1
    arg = 2
    simulation = 3
