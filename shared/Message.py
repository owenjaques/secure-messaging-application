from dataclasses import dataclass
from datetime import datetime as dt


@dataclass
class Message():
    recepient: str
    sender: str
    sender_identity_key: str
    ephemeral_key: str
    ciphertext: str
    pk_idx: int
    is_image: bool = False
    timestamp: str = None
    read: bool = False

    def to_dict(self):
        return {
            "recepient": self.recepient,
            "sender": self.sender,
            "sender_identity_key": self.sender_identity_key,
            "ephemeral_key": self.ephemeral_key,
            "ciphertext": self.ciphertext,
            "pk_idx": self.pk_idx,
            "is_image": self.is_image,
            "timestamp": self.timestamp,
            "read": self.read
        }

    @staticmethod
    def from_dict(d):
        return Message(
            recepient=d["recepient"],
			sender=d["sender"],
			sender_identity_key=d["sender_identity_key"],
			ephemeral_key=d["ephemeral_key"],
			ciphertext=d["ciphertext"],
			pk_idx=d["pk_idx"],
            timestamp=d.get("timestamp"),
			is_image= d.get("is_image") or False,
            read= d.get("read") or False
        )