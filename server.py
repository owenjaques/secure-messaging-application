from flask import Flask, request
from ServerUser import User

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/signup", methods=["POST"])
def signup():
    params = {
        "username": request.get_json().get("username"),
        "identity": request.get_json().get("identity"),
        "pk_sig": request.get_json().get("pk_sig"),
        "signed_pk": request.get_json().get("signed_pk"),
        "prekeys": request.get_json().get("prekeys")
    }
    
    user = User(params["username"], params["identity"], params["pk_sig"], params["signed_pk"], params["prekeys"])
