#!/usr/bin/python3

# SPDX-FileCopyrightText: 2024-2025 Artiom Mocrenco <artiom.mocrenco@gmail.com>
# SPDX-FileCopyrightText: 2025-present Mateusz Nalewajski
# SPDX-License-Identifier: AGPL-3.0

import base64
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import traceback
from sys import stdout

import google.protobuf.message
import meshtastic.ble_interface
import meshtastic.serial_interface
import meshtastic.tcp_interface
import paho.mqtt.client as mqtt
import redis
from google.protobuf.json_format import MessageToDict
from meshtastic import protocols
from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from prometheus_client import start_http_server
from pubsub import pub
from redis import BusyLoadingError
from redis.backoff import ExponentialBackoff
from redis.retry import Retry

from meshtastic_prometheus_exporter.crypto import (
    decrypt_packet,
    generate_channel_hash,
    get_key,
)
from meshtastic_prometheus_exporter.metrics import *
from meshtastic_prometheus_exporter.neighborinfo import on_meshtastic_neighborinfo_app
from meshtastic_prometheus_exporter.nodeinfo import on_meshtastic_nodeinfo_app
from meshtastic_prometheus_exporter.position import on_meshtastic_position_app
from meshtastic_prometheus_exporter.telemetry import on_meshtastic_telemetry_app
from meshtastic_prometheus_exporter.traceroute import on_meshtastic_traceroute_app
from meshtastic_prometheus_exporter.util import (
    get_decoded_node_metadata_from_redis,
    get_node_by_id,
    save_node_info_in_redis,
    save_node_metadata_in_redis,
)

config = {
    "meshtastic_interface": os.environ.get("MESHTASTIC_INTERFACE"),
    "interface_serial_device": os.environ.get("SERIAL_DEVICE", "/dev/ttyACM0"),
    "interface_tcp_addr": os.environ.get("INTERFACE_TCP_ADDR"),
    "interface_tcp_port": os.environ.get("INTERFACE_TCP_PORT", meshtastic.tcp_interface.DEFAULT_TCP_PORT),
    "interface_ble_addr": os.environ.get("INTERFACE_BLE_ADDR", "/dev/ttyACM0"),
    "mqtt_address": os.environ.get("MQTT_ADDRESS", "mqtt.meshtastic.org"),
    "mqtt_use_tls": os.environ.get("MQTT_USE_TLS", False),
    "mqtt_port": os.environ.get("MQTT_PORT", 1883),
    "mqtt_keepalive": os.environ.get("MQTT_KEEPALIVE", 15),
    "mqtt_username": os.environ.get("MQTT_USERNAME"),
    "mqtt_password": os.environ.get("MQTT_PASSWORD"),
    "mqtt_topic": os.environ.get("MQTT_TOPIC", "msh/EU_433/#"),
    "prometheus_server_addr": os.environ.get("PROMETHEUS_SERVER_ADDR", "0.0.0.0"),
    "prometheus_server_port": os.environ.get("PROMETHEUS_SERVER_PORT", 9464),
    "redis_url": os.environ.get("REDIS_URL", "redis://localhost:6379"),
    "log_level": os.environ.get("LOG_LEVEL", "INFO"),
    "flood_expire_time": os.environ.get("FLOOD_EXPIRE_TIME", 10 * 60),
    "channel_psks": os.environ.get(
        "CHANNEL_PSKS",
        '{"MediumFast": "AQ==", "LongFast": "AQ==", "ShortFast": "AQ=="}',
    ),
    "longitude": float(os.environ.get("LONGITUDE", 21.012229)),
    "latitude": float(os.environ.get("LATITUDE", 52.229676)),
    "distance": float(os.environ.get("DISTANCE", 0)),
}

iface = None
logger = None
redis_pool = None
exit_event = threading.Event()
reference_point = None
channel_keys = {}


def on_connect(client, userdata, flags, reason_code, properties):
    global logger

    if reason_code.is_failure:
        logger.warning(
            f"Failed to connect to MQTT server with result code {reason_code}. loop_forever() will retry connection"
        )
    else:
        logger.info(f"Connected to MQTT server with result code {reason_code}")
        client.subscribe(config["mqtt_topic"])


def on_meshtastic_mesh_packet(user_id, packet):
    global logger
    global redis_pool

    r = redis.Redis(connection_pool=redis_pool)

    _id = packet.get("id")

    if _id is None:
        return

    _from = packet["from"]
    to = packet["to"]

    decoded = packet.get("decoded", {})

    payload = decoded.get("payload")
    portnum = decoded.get("portnum", "UNKNOWN")

    encrypted = packet.get("encrypted")
    channel_hash = packet.get("channel")
    channel_key = channel_keys.get(channel_hash)

    if encrypted and channel_key:
        decrypted = decrypt_packet(channel_key, _from, _id, base64.b64decode(encrypted))
        data = mesh_pb2.Data.FromString(decrypted)
        payload = None

        try:
            payload = data.payload
            portnum = portnums_pb2.PortNum.Name(data.portnum)
            decoded = packet["decoded"] = MessageToDict(data) | {"portnum": portnum, "payload": payload}

        except Exception:
            logger.warning(f"Decryption failed for packet {_id} from {_from}")

        if payload is not None:
            encrypted = False

    source = decoded.get("source")
    dest = decoded.get("dest")
    request_id = decoded.get("requestId")
    want_response = decoded.get("wantResponse")

    if not source:
        source = _from

    if not dest:
        dest = to

    if isinstance(payload, str):
        payload = base64.b64decode(payload)

    logger.info(f"Received packet {_id} from {_from} with PortNum {portnum}")

    if portnum == "NODEINFO_APP":
        if payload:
            packet["decoded"]["user"] = MessageToDict(mesh_pb2.User.FromString(payload))

        on_meshtastic_nodeinfo_app(r, packet)

    from_id = get_decoded_node_metadata_from_redis(r, _from, "id")
    from_long_name = get_decoded_node_metadata_from_redis(r, _from, "long_name")
    from_short_name = get_decoded_node_metadata_from_redis(r, _from, "short_name")

    to_id = get_decoded_node_metadata_from_redis(r, to, "id")
    to_long_name = get_decoded_node_metadata_from_redis(r, packet["to"], "long_name")
    to_short_name = get_decoded_node_metadata_from_redis(r, packet["to"], "short_name")

    source_id = get_decoded_node_metadata_from_redis(r, source, "id")
    source_long_name = get_decoded_node_metadata_from_redis(r, source, "long_name")
    source_short_name = get_decoded_node_metadata_from_redis(r, source, "short_name")

    dest_id = get_decoded_node_metadata_from_redis(r, dest, "id")
    dest_long_name = get_decoded_node_metadata_from_redis(r, dest, "long_name")
    dest_short_name = get_decoded_node_metadata_from_redis(r, dest, "short_name")

    user = get_node_by_id(r, user_id)
    user_short_name = get_decoded_node_metadata_from_redis(r, user, "short_name")
    user_long_name = get_decoded_node_metadata_from_redis(r, user, "long_name")

    unique = r.set(str(_id), 1, nx=True, ex=config["flood_expire_time"])

    direct = packet.get("hopLimit", -1) == packet.get("hopStart")
    rx_snr = packet.get("rxSnr")

    known_source = source_long_name is not None
    known_user = user is not None

    # https://buf.build/meshtastic/protobufs/file/main:meshtastic/portnums.proto
    attributes = {
        "user": user,
        "user_id": user_id,
        "user_short_name": user_short_name,
        "user_long_name": user_long_name,
        "from": _from,
        "from_id": from_id,
        "from_long_name": from_long_name,
        "from_short_name": from_short_name,
        "to": to,
        "to_id": to_id,
        "to_long_name": to_long_name,
        "to_short_name": to_short_name,
        "source": source,
        "source_id": source_id,
        "source_long_name": source_long_name,
        "source_short_name": source_short_name,
        "dest": dest,
        "dest_id": dest_id,
        "dest_long_name": dest_long_name,
        "dest_short_name": dest_short_name,
        "request_id": request_id,
        "want_response": want_response,
        "channel": packet.get("channel"),
        "type": portnum,
        "want_ack": packet.get("wantAck", False),
        "via_mqtt": packet.get("viaMqtt", False),
        "rx_snr": rx_snr,
    }

    attributes = {k: v for k, v in attributes.items() if v is not None}

    logger.info(f"Retrieved attributes for packet {_id} {json.dumps(attributes)}")

    if portnum == "POSITION_APP":
        if payload:
            packet["decoded"]["position"] = MessageToDict(mesh_pb2.Position.FromString(payload))

        on_meshtastic_position_app(r, packet, attributes, reference_point)

    if not known_source:
        logger.info(f"NodeInfo is now yet known for Node {_from}, ignoring the packet {_id}")
        return

    if not known_user:
        logger.info(f"NodeInfo is now yet known for User {user_id}, ignoring the packet {_id}")
        return

    if config["distance"] > 0:
        origin = _from
        distance = get_decoded_node_metadata_from_redis(r, origin, "distance")

        if not distance and known_user:
            origin = user
            distance = get_decoded_node_metadata_from_redis(r, origin, "distance")

        if not distance:
            logger.info(f"Distance is unknown for Node {origin}, ignoring the packet {_id}")
            return

        distance = float(distance)

        if distance > config["distance"]:
            logger.info(f"Node {origin} is too far from us ({distance} km), ignoring the packet {_id}")
            return

    node_last_heard_attributes = {
        "source": source,
        "source_id": source_id,
        "source_long_name": source_long_name,
        "source_short_name": source_short_name,
        "portnum": portnum,
    }
    node_last_heard_attributes = {k: v for k, v in node_last_heard_attributes.items() if v is not None}
    meshtastic_node_last_heard_timestamp_seconds.set(time.time(), attributes=node_last_heard_attributes)

    node_hop_start_attributes = {
        "source": source,
        "source_id": source_id,
        "source_long_name": source_long_name,
        "source_short_name": source_short_name,
    }
    node_hop_start_attributes = {k: v for k, v in node_hop_start_attributes.items() if v is not None}
    meshtastic_node_hop_start.set(packet.get("hopStart"), attributes=node_hop_start_attributes)

    if portnum == "TRACEROUTE_APP" and not encrypted:
        if payload:
            packet["decoded"]["traceroute"] = MessageToDict(mesh_pb2.RouteDiscovery.FromString(payload))
        on_meshtastic_traceroute_app(r, packet, attributes)

    elif direct and rx_snr:
        mesh_packets_snr_decibels_attributes = {
            "user": user,
            "user_id": user_id,
            "user_long_name": user_long_name,
            "user_short_name": user_short_name,
            "from": packet["from"],
            "from_id": from_id,
            "from_long_name": from_long_name,
            "from_short_name": from_short_name,
            "source": "direct",
        }
        mesh_packets_snr_decibels_attributes = {
            k: v for k, v in mesh_packets_snr_decibels_attributes.items() if v is not None
        }
        meshtastic_mesh_packets_snr_decibels.set(
            rx_snr,
            attributes=mesh_packets_snr_decibels_attributes,
        )

    if not unique:
        logger.info(f"Skipping duplicated packet {_id}")
        return

    mesh_packets_total_attributes = {
        "source": source,
        "source_id": source_id,
        "source_long_name": source_long_name,
        "source_short_name": source_short_name,
        "to": to,
        "to_id": to_id,
        "to_long_name": to_long_name,
        "to_short_name": to_short_name,
        "type": portnum,
    }
    mesh_packets_total_attributes = {k: v for k, v in mesh_packets_total_attributes.items() if v is not None}
    meshtastic_mesh_packets_total.add(1, attributes=mesh_packets_total_attributes)

    if encrypted:
        logger.info(f"Skipping encrypted packet {_id}")
        return

    if portnum == "TELEMETRY_APP":
        if payload:
            packet["decoded"]["telemetry"] = MessageToDict(telemetry_pb2.Telemetry.FromString(payload))
        return on_meshtastic_telemetry_app(r, packet, attributes)

    elif portnum == "NEIGHBORINFO_APP":
        if payload:
            packet["decoded"]["neighborinfo"] = MessageToDict(mesh_pb2.NeighborInfo.FromString(payload))
        return on_meshtastic_neighborinfo_app(r, packet, attributes)


def on_message(client, userdata, msg):
    global logger

    if "/json/" in msg.topic:
        return

    if "/map/" in msg.topic:
        return

    try:
        envelope = mqtt_pb2.ServiceEnvelope.FromString(msg.payload)
        packet = envelope.packet

        user_id = msg.topic.split("/")[-1]
        if not user_id or not re.fullmatch(r"^![a-z0-9]{8}", user_id):
            user_id = None

        logger.debug(f"Received UTF-8 payload `{MessageToDict(envelope)}` user {user_id} on on `{msg.topic}` topic")
        on_native_message(user_id, MessageToDict(packet), None)

    except Exception as e:
        logger.error(f"{e} occurred while processing payload {msg.payload} from topic {msg.topic}")


def on_native_message(user_id, packet, interface):
    global logger

    try:
        on_meshtastic_mesh_packet(user_id, packet)
    except Exception as e:
        logger.error(f"{e} occurred while processing MeshPacket {packet}")


def on_native_connection_established(interface, topic=pub.AUTO_TOPIC):
    global logger

    logger.info(f"Connected to device over {type(interface).__name__}")


def on_native_connection_lost(interface, topic=pub.AUTO_TOPIC):
    global exit_event

    logger.warning(f"Lost connection to device over {type(interface).__name__}")
    exit_event.set()


def main():
    global iface
    global logger
    global redis_pool
    global exit_event
    global reference_point
    global channel_keys

    logger = logging.getLogger("meshtastic_prometheus_exporter")
    logger.propagate = False

    logger.setLevel(getattr(logging, config["log_level"].upper()))

    handler = logging.StreamHandler(stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - meshtastic_prometheus_exporter - %(levelname)s - %(message)s")
    )

    logger.addHandler(handler)

    try:
        reader = PrometheusMetricReader()
        start_http_server(port=config["prometheus_server_port"], addr=config["prometheus_server_addr"])

        provider = MeterProvider(
            resource=Resource.create(attributes={"service.name": "meshtastic"}),
            metric_readers=[reader],
            # views=[],
        )
        metrics.set_meter_provider(provider)
        meter = metrics.get_meter("meshtastic_prometheus_exporter")

        redis_pool = redis.ConnectionPool.from_url(
            config["redis_url"],
            protocol=2,
            retry=Retry(ExponentialBackoff(10, 1), 3),
            retry_on_error=[BusyLoadingError, ConnectionError, TimeoutError],
        )

    except Exception as e:
        logger.fatal(f"Exception occurred while starting up: {';'.join(traceback.format_exc().splitlines())}")
        sys.exit(1)

    channel_psks = json.loads(config["channel_psks"])

    for name, psk in channel_psks.items():
        key = get_key(base64.b64decode(psk))
        _hash = generate_channel_hash(name, key)
        channel_keys[_hash] = key

    try:
        reference_point = None
        if config["longitude"] and config["latitude"]:
            reference_point = (config["longitude"], config["latitude"])

        if config.get("meshtastic_interface") not in ["MQTT", "SERIAL", "TCP", "BLE"]:
            logger.fatal(
                f"Invalid value for MESHTASTIC_INTERFACE: {config['meshtastic_interface']}. Must be one of: MQTT, SERIAL, TCP, BLE"
            )
            sys.exit(1)

        pub.subscribe(on_native_message, "meshtastic.receive")
        pub.subscribe(on_native_connection_established, "meshtastic.connection.established")
        pub.subscribe(on_native_connection_lost, "meshtastic.connection.lost")

        if config.get("meshtastic_interface") == "SERIAL":
            iface = meshtastic.serial_interface.SerialInterface(devPath=config.get("serial_device"))
        elif config.get("meshtastic_interface") == "TCP":
            iface = meshtastic.tcp_interface.TCPInterface(
                hostname=config.get("interface_tcp_addr"),
                portNumber=int(config.get("interface_tcp_port")),
            )
        elif config.get("meshtastic_interface") == "BLE":
            iface = meshtastic.ble_interface.BLEInterface(
                address=config.get("interface_ble_addr"),
            )
        elif config.get("meshtastic_interface") == "MQTT":
            mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

            mqttc.on_connect = on_connect
            mqttc.on_message = on_message

            if int(config["mqtt_use_tls"]) == 1:
                tlscontext = ssl.create_default_context()
                mqttc.tls_set_context(tlscontext)

            if config["mqtt_username"]:
                mqttc.username_pw_set(config["mqtt_username"], config["mqtt_password"])

            mqttc.connect(
                config["mqtt_address"],
                int(config["mqtt_port"]),
                keepalive=int(config["mqtt_keepalive"]),
            )

            mqttc.loop_forever()

        if hasattr(iface, "nodes") and len(iface.nodes) > 0:
            logger.info(f"NodeDB is available, saving metadata in Redis for {len(iface.nodes.values())} nodes")

            r = redis.Redis(connection_pool=redis_pool)
            for n in iface.nodes.values():
                save_node_info_in_redis(
                    r,
                    n["num"],
                    {
                        "longName": n["user"]["longName"],
                        "shortName": n["user"]["shortName"],
                        "hwModel": n["user"]["hwModel"],
                    },
                )
        else:
            logger.warning(
                "Device NodeDB is empty or not available. NodeInfo are not sent often, so populating local NodeDB (stored in Redis) may take from several hours to several days or more."
            )
            logger.warning(
                "Consider first connecting a node with populated NodeDB over Serial, BLE or TCP interface, so that Redis is populated with NodeInfo faster."
            )

        while not exit_event.wait():
            pass

    except KeyboardInterrupt:
        pass

    except SystemExit:
        pass

    except Exception as e:
        logger.fatal(f"Exception occurred while starting up: {';'.join(traceback.format_exc().splitlines())}")
        sys.exit(1)


if __name__ == "__main__":
    main()
