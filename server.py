#!/usr/bin/env python3

from flask import Flask, request, Response, jsonify
from ServerUser import User, UserStore

app = Flask(__name__)
store = UserStore()

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = {
            "username":     request.form.get("username"),
            "password":     request.form.get("password"),
            "identity":     request.form.get("identity"),
            "pk_sig":       request.form.get("pk_sig"),
            "signed_pk":    request.form.get("signed_pk")
        }

        # Prekey formatting is fucked, even entries are the index for the next odd entry
        pk_list = request.form.getlist("prekeys")
        prekeys = []
        for i in range(0, len(pk_list), 2):
            prekeys.append((i, pk_list[i+1]))
        data["prekeys"] = prekeys

        for k,v in data.items():
            if v == None:
                return Response(f"Missing key {k}")
        
        store.signup(data)
        return Response("Success")
    except Exception as e:
        print(e)
    
@app.route("/keybundle/<username>", methods=["GET"])
def keybundle(username):
    user = store.get_user(username)
    if user:
        return jsonify(user.get_keybundle())
    else:
        return Response(f"User {username} not found")
    


if __name__ == "__main__":
    app.run(port=5000)
