from dataclasses import dataclass
import json


@dataclass
class ClientConfiguration:
    kms_server_url: str
    kms_access_token: str = None

    @staticmethod
    def from_json(json_str: str):
        data = json.loads(json_str)
        return ClientConfiguration(**data)
