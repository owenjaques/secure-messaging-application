import json
from MessageBox import MessageBox

class User:
    username = None
    password = None
    identity = None
    pk_sig = None
    signed_pk = None
    prekeys = None
    message_box = None
    message_box_path = None

    def __init__(self, 
                username, 
                password,
                identity,
                pk_sig,
                signed_pk,
                prekeys,
                burnt_keys = [],
                message_box_path = None):
        self.username = username
        self.password = password
        self.identity = identity
        self.pk_sig = pk_sig
        self.signed_pk = signed_pk
        self.prekeys = prekeys # List of tuples (idx, prekey)
        self.burnt_keys = burnt_keys
        self.message_box = MessageBox(self.message_box_path)

        print(f"User init complete with {len(prekeys)} prekeys")


    def receive_message(self, message):
        self.message_box.add(message)

    def to_dict(self):
        return {
                "username":     self.username,
                "password":     self.password,
                "identity":     self.identity,
                "pk_sig":       self.pk_sig,
                "signed_pk":    self.signed_pk,
                "prekeys":      self.prekeys,
                "burnt_keys":   self.burnt_keys
            }

    @staticmethod
    def from_dict(user_dict):
        return User(user_dict["username"],
                    user_dict["password"],
                    user_dict["identity"],
                    user_dict["pk_sig"],
                    user_dict["signed_pk"],
                    user_dict["prekeys"],
                    user_dict.get("burnt_keys"))


    def validate_password(self, password):
        assert self.password == password, "Invalid password"


    def get_keybundle(self):
        """
            Returns a dict representing a key bundle for the first message between users
        """
        key_idx, prekey = self.prekeys[0]
        del(self.prekeys[0])
        return {
            "identity":     self.identity,
            "pk_sig":       self.pk_sig,
            "signed_pk":    self.signed_pk,
            "prekey":       prekey,
            "prekey_idx":   key_idx
        }

class UserStore:
    _userstore = dict()

    def __init__(self):
        try:
            with open("users.json") as f:
                self._userstore = json.load(f)
        except FileNotFoundError:
            print("No user file found, one will be created once a user signs up")

    def get_user(self, username):
        if username in self._userstore.keys():
            return User.from_dict(self._userstore[username])
        
        return None

    def get_all_users(self):
        """
        Returns a dict of all users objects
        """
        users = [self.get_user(username) for username in self._userstore.keys()]
        return users

    def write_user(self, user):
        # Insert/update user in db
        with open("users.json", "r+") as f:
            file_data = json.load(f)
            file_data.update({user.username: user.to_dict()})
            f.seek(0)
            json.dump(file_data, f)
    
        print(f"User {user.username} written to disk")

    def signup(self, user_dict):
        if not self.get_user(user_dict['username']):
            user = User.from_dict(user_dict)
            self.write_user(user)

            userstore_dict = {
                user_dict["username"]:  user_dict
            }
            self._userstore.update(userstore_dict)
        
        
