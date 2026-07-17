"""Mongo (de)serialization helpers."""

from datetime import datetime


def prepare_for_mongo(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
    return data


def parse_from_mongo(item):
    if isinstance(item, dict):
        for key, value in item.items():
            if isinstance(value, str) and key.endswith("_at"):
                try:
                    item[key] = datetime.fromisoformat(value)
                except Exception:
                    pass
    return item
