#!/usr/bin/env python3

from flask import Flask, request, Response
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
            "username": request.form.get("username"),
            "identity": request.form.get("identity"),
            "pk_sig":   request.form.get("pk_sig"),
            "signed_pk":    request.form.get("signed_pk"),
            "prekeys":  request.form.getlist("prekeys")
        }
        for k,v in data.items():
            if v == None:
                return Response(f"Missing key {k}")
        
        store.signup(data)
        return Response("Success")
    except Exception as e:
        print(e)
    
if __name__ == "__main__":
    app.run(port=5000)
