import json
import logging
import time

from meshtastic_prometheus_exporter.metrics import *
from meshtastic_prometheus_exporter.util import get_decoded_node_metadata_from_redis

logger = logging.getLogger("meshtastic_prometheus_exporter")


def on_meshtastic_traceroute_app(r, packet, attributes):
    traceroute = packet["decoded"].get("traceroute", {})

    logger.debug(f"Received MeshPacket {packet['id']} with Traceroute `{json.dumps(traceroute, default=repr)}`")

    source = attributes["source"]
    response = bool(attributes.get("request_id"))

    snrTowards = list(map(lambda s: float(s) / 4, traceroute.get("snrTowards", [])))
    snrBack = list(map(lambda s: float(s) / 4, traceroute.get("snrBack", [])))

    routeTowards = traceroute.get("route", [])
    routeBack = traceroute.get("routeBack", [])

    if response:
        routeBack = [packet["from"]] + routeBack

        if packet["to"] == attributes["user"]:
            routeBack = routeBack + [attributes["user"]]
            snrBack = snrBack + [attributes["rx_snr"]]

        routeTowards = [packet["to"]] + routeTowards + [packet["from"]]

    else:
        routeTowards = [packet["from"]] + routeTowards

        if packet["from"] == attributes["user"]:
            routeTowards = routeTowards + [attributes["user"]]
            snrTowards = snrTowards + [attributes["rx_snr"]]

    logger.debug(
        f"Traceroute response={response} routeTowards={routeTowards} routeBack={routeBack} snrTowards={snrTowards} snrBack={snrBack}"
    )

    def process_hops(route, snr, direction):
        for i in range(1, len(route)):
            _from = route[i - 1]
            from_id = get_decoded_node_metadata_from_redis(r, _from, "id")

            if not from_id:
                continue

            from_long_name = get_decoded_node_metadata_from_redis(r, _from, "long_name")
            from_short_name = get_decoded_node_metadata_from_redis(r, _from, "short_name")

            user = route[i]
            user_id = get_decoded_node_metadata_from_redis(r, user, "id")

            if not user_id:
                continue

            user_short_name = get_decoded_node_metadata_from_redis(r, user, "short_name")
            user_long_name = get_decoded_node_metadata_from_redis(r, user, "long_name")

            rx_snr = snr[i - 1]

            hop_attributes = {
                "user": user,
                "user_id": user_id,
                "user_long_name": user_long_name,
                "user_short_name": user_short_name,
                "from": _from,
                "from_id": from_id,
                "from_long_name": from_long_name,
                "from_short_name": from_short_name,
                "source": "traceroute",
            }

            meshtastic_mesh_packets_snr_decibels.set(rx_snr, attributes=hop_attributes)

            logger.info(
                f"Traceroute hop attributes for direction {direction} - {json.dumps(hop_attributes)}, SNR {rx_snr} dB"
            )

    process_hops(routeTowards, snrTowards, "towards")
    process_hops(routeBack, snrBack, "back")
