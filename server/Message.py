from dataclasses import dataclass
from datetime import datetime as dt

@dataclass
class Message():
    recepient: str
    sender: str
    ciphertext: str
    is_image: bool
    timestamp: str
    read: bool = False

