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
    is_image: bool
    timestamp: str
    read: bool = False

