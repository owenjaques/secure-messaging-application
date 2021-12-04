class MessageBox:
    """
    Holds Message objects for a given user
    TODO: Store messages to disk, add from_file method
    """
    message_box_path = None
    _messages = []

    def __init__(self, message_box_path):
        self.load_messages(message_box_path)

    def fetch_new(self):
        return [i for i in self._messages if not i.read]

    def fetch_all(self):
        return self._messages

    def add(self, msg):
        self._messages.append(msg)

    def load_messages(self, path):
        pass