class MessageBox:
    """
    Holds Message objects for a given user
    """
    user = None
    messages = []

    def fetch_new(self):
        return [i for i in self.messages if not i.read]

    def fetch_all(self):
        return self.messages

    def add(self, msg):
        self.messages.append(msg)