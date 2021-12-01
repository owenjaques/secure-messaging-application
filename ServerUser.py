import json

class User:
    username = None
    identity = None
    pk_sig = None
    signed_pk = None
    prekeys = None

    def __init__(self, 
                username, 
                identity,
                pk_sig,
                signed_pk,
                prekeys):
        self.username = username
        self.identity = identity
        self.pk_sig = pk_sig
        self.signed_pk = signed_pk
        self.prekeys = prekeys

        print(f"User init complete with {len(prekeys)} prekeys")

    def to_dict(self):
        return {
                "username":     self.username,
                "identity":     self.identity,
                "pk_sig":       self.pk_sig,
                "signed_pk":    self.signed_pk,
                "prekeys":      self.prekeys
            }

    @staticmethod
    def from_dict(user_dict):
        return User(user_dict["username"],
                    user_dict["identity"],
                    user_dict["pk_sig"],
                    user_dict["signed_pk"],
                    user_dict["prekeys"])


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

    def write_user(self, user):
        # Insert/update user in db
        with open("users.json", "r+") as f:
            file_data = json.load(f)
            file_data.update({user["username"]: user})
            f.seek(0)
            json.dump(file_data, f)
    
        print(f"User {user['username']} written to disk")

    def signup(self, user_dict):
        user = User.from_dict(user_dict)
        self.write_user(user)

        userstore_dict = {
            user_dict["username"]:  user_dict
        }
        self._userstore.update(userstore_dict)
        
        
