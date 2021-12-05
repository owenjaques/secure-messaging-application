#!/usr/bin/env python3

from flask import Flask, request, Response, jsonify
from ServerUser import User, UserStore
from Message import Message
from datetime import datetime as dt

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
            "signing_id":   request.form.get("signing_id"),
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
    
@app.route("/send", methods=["POST"])
def send_message():
    try:
        sender = request.form.get("from")
        identity = request.form.get("identity_key")
        ephemeral_key = request.form.get("ephemeral_key")
        recepient = request.form.get("to")
        text = request.form.get("message")
        is_image = request.form.get("is_image")
        pk_idx = request.form.get("prekey_index")

        # TODO: check if recepient and sender exist in userstore
        user = store.get_user(recepient)
        user.receive_message(Message(recepient=recepient,
                                    sender=sender,
                                    sender_identity_key=identity,
                                    ephemeral_key=ephemeral_key,
                                    ciphertext=text,
                                    pk_idx=pk_idx,
                                    is_image=is_image,
                                    timestamp=dt.now().strftime("%d/%m/%Y %H:%M:%S")))

        return Response("Message sent")
        

    except Exception as e:
        print(e)

@app.route("/keys", methods=["GET"])
def published_keys():
    """
    Displays a list of published keys and the userpair.
    A key is published after a message has been encrypted with it
    """
    html = ""
    for user in store.get_all_users():
        html += f"<h3>{user.username}</h3><br>"
        for key in user.burnt_keys:
            html += f"<p>{key[1]}</p><br>"

        html += "<br><br><br>"

    return html

@app.route("/publishkey")
def publish_key():
    """
    POST params:
        Username
        Password
        key to publish
    """
    try:
        username = request.form.get("username")
        password = request.form.get("password")
        key = request.form.get("key")

        user = store.get_user(username)
        try:
            user.validate_password(password)
        except Exception:
            return Response("Invalid password", status=401)
            
        user.burnt_keys.append(key)

    except Exception as e:
        print(e)

@app.route("/inbox", methods=["POST"])
def check_inbox():
    """
    POST params:
        Username
        Password
        Unread/all messages
    """
    try:
        username = request.form.get("username")
        password = request.form.get("password")
        to_check = request.form.get("to_get")

        user = store.get_user(username)
        try:
            user.validate_password(password)
        except Exception:
            return Response("Invalid password", status=401)

        if to_check == "all":
            return jsonify(user.message_box.fetch_all)
        elif to_check == "new":
            return jsonify(user.message_box.fetch_new)

            

    except Exception as e:
        print(e)


if __name__ == "__main__":
    app.run(port=5000)
