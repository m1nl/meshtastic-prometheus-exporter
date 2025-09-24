import json
import logging
import time

from meshtastic_prometheus_exporter.metrics import *
from meshtastic_prometheus_exporter.util import save_node_position_in_redis

logger = logging.getLogger("meshtastic_prometheus_exporter")


def on_meshtastic_position_app(redis, packet, attributes, reference_point: tuple[float, float] = None):
    position = packet["decoded"]["position"]

    logger.debug(f"Received MeshPacket {packet['id']} with Position `{json.dumps(position, default=repr)}`")

    source = packet["decoded"].get("source", packet["from"])

    if source:
        mapping = save_node_position_in_redis(redis, source, position, reference_point)
        logger.info(f"Distance to node {mapping['distance']} km")
