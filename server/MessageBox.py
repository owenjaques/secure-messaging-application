class MessageBox:
    """
    Holds Message objects for a given user
    """
    message_box_path = None
    _messages = []

    def __init__(self, message_box_path):
        self.load_messages(message_box_path)

    def fetch_new(self):
        return [i.view() for i in self._messages if not i.read]

    def fetch_all(self):
        return [i.view() for i in self._messages]

    def add(self, msg):
        self._messages.append(msg)

    def load_messages(self, path):
        pass