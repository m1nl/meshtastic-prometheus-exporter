import json
import logging

from meshtastic_prometheus_exporter.metrics import *
from meshtastic_prometheus_exporter.util import get_decoded_node_metadata_from_redis

logger = logging.getLogger("meshtastic_prometheus_exporter")


def on_meshtastic_neighborinfo_app(redis, packet, attributes):
    neighbor_info = packet["decoded"]["neighborinfo"]
    logger.debug(f"Received MeshPacket {packet['id']} with NeighborInfo `{json.dumps(neighbor_info, default=repr)}`")

    source = attributes["source"]
    source_id = attributes["source_id"]
    source_long_name = attributes["source_long_name"]
    source_short_name = attributes["source_short_name"]

    if not "neighbors" in neighbor_info:
        return

    for n in neighbor_info["neighbors"]:
        neighbor_source = n["nodeId"]
        neighbor_source_id = get_decoded_node_metadata_from_redis(redis, neighbor_source, "id")

        if not neighbor_source_id:
            continue

        rx_snr = n.get("snr")

        if rx_snr is None:
            continue

        neighbor_source_long_name = get_decoded_node_metadata_from_redis(redis, neighbor_source, "long_name")
        neighbor_source_short_name = get_decoded_node_metadata_from_redis(redis, neighbor_source, "short_name")

        hop_attributes = {
            "user": source,
            "user_id": source_id,
            "user_long_name": source_long_name,
            "user_short_name": source_short_name,
            "from": neighbor_source,
            "from_id": neighbor_source_id,
            "from_long_name": neighbor_source_long_name,
            "from_short_name": neighbor_source_short_name,
            "source": "neighborinfo",
        }

        meshtastic_mesh_packets_snr_decibels.set(rx_snr, attributes=hop_attributes)
