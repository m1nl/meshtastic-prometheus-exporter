from geopy.distance import distance, lonlat


def _get_node_distance(a: tuple[float, float], b: tuple[float, float]) -> float:
    return round(distance(lonlat(*a), lonlat(*b)).km, 2)


def get_node_by_id(redis, _id: str) -> int:
    if not _id:
        return None

    node = redis.get(_id)

    if node is None:
        return None

    return int(node)


def get_decoded_node_metadata_from_redis(redis, node: int, metadata: str):
    if not node:
        return None

    try:
        value = redis.hget(node, metadata)

        if value:
            value = value.decode("utf-8")
    except UnicodeDecodeError:
        value = None

    return value


def save_node_metadata_in_redis(redis, node: int, key: str, value: any, ex=3600 * 72) -> dict:
    mapping = {key: str(value)}

    redis.hset(node, mapping=mapping)
    redis.expire(node, ex)

    return mapping


def save_node_info_in_redis(redis, node: int, node_info: dict, ex=3600 * 72) -> dict:
    mapping = {
        "id": node_info["id"],
        "long_name": node_info["longName"],
        "short_name": node_info["shortName"],
        "hw_model": node_info["hwModel"],
        "is_licensed": str(node_info.get("isLicensed", False)),
    }

    redis.hset(
        node,
        mapping=mapping,
    )

    redis.expire(node, ex)
    redis.set(node_info["id"], node, ex=ex)

    return mapping


def save_node_position_in_redis(
    redis, node: int, position: dict, reference_point: tuple[float, float] = None, ex=3600 * 72
) -> dict:
    longitude = float(position["longitudeI"]) / 1e7
    latitude = float(position["latitudeI"]) / 1e7
    altitude = None

    if "altitude" in position:
        altitude = round(float(position["altitude"]), 0)

    distance = 0

    if reference_point:
        distance = _get_node_distance((longitude, latitude), reference_point)

    mapping = {
        "longitude": longitude,
        "latitude": latitude,
        "altitude": altitude,
        "location_source": position.get("locationSource", "unknown"),
        "precision_bits": int(position.get("precisionBits", 0)),
        "distance": distance,
    }
    mapping = {k: v for k, v in mapping.items() if v is not None}

    redis.hset(node, mapping=mapping)
    redis.expire(node, ex)

    return mapping
