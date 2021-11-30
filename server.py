#!/usr/bin/env python3

from flask import Flask, request
from ServerUser import User, UserStore

app = Flask(__name__)
store = UserStore()

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/signup", methods=["POST"])
def signup():
    try:
        store.signup(request.data)
    except Exception as e:
        print(e)
    
