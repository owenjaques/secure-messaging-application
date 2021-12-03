from dataclasses import dataclass

@dataclass
class MessageBox:
    """
    Holds Message objects for a given user
    TODO: Store messages to disk, add from_file method
    """
    user = None
    message_box_path = None
    messages = []

    def fetch_new(self):
        return [i for i in self.messages if not i.read]

    def fetch_all(self):
        return self.messages

    def add(self, msg):
        self.messages.append(msg)