import json
import logging
import time

from meshtastic_prometheus_exporter.metrics import *
from meshtastic_prometheus_exporter.util import (
    get_decoded_node_metadata_from_redis,
    save_node_info_in_redis,
)

logger = logging.getLogger("meshtastic_prometheus_exporter")


def on_meshtastic_nodeinfo_app(redis, packet):
    node_info = packet["decoded"]["user"]

    logger.debug(f"Received MeshPacket {packet['id']} with NodeInfo `{json.dumps(node_info, default=repr)}`")

    source = packet["decoded"].get("source", packet["from"])

    if source:
        save_node_info_in_redis(redis, source, node_info)
