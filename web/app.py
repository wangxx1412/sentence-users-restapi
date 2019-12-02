from flask import Flask, jsonify, request
from flask_restful import Api, Resource
import bcrypt
from pymongo import MongoClient

app = Flask(__name__)
api = Api(app)

# Making connection with MongoClient
client = MongoClient("mongodb://db:27017")
# Getting a db
db = client['sentenceDB']
# Getting a collection
users = db["Users"]


class Register(Resource):
    def post(self):
        # Get postData by user
        postData = request.get_json()

        # Get the data
        username = postData["username"]
        password = postData["password"]

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # store username and pw into db
        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Sentence": "",
            "Tokens": 10
        })

        retJson = {
            "status": 200,
            "msg": "Sign up successfully"
        }

        return jsonify(retJson)


def verifyPw(username, password):
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def countTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens


class Store(Resource):
    def post(self):
        postData = request.get_json()

        username = postData["username"]
        password = postData["password"]
        sentence = postData["sentence"]

        # verify username and pw
        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status": 302,
                "msg": "Invalid credentials"
            }
            return jsonify(retJson)

        # verify enough tokens
        num_tokens = countTokens(username)
        if not num_tokens > 0:
            retJson = {
                "status": 301,
                "msg": "Not enough tokens"
            }
            return retJson

        # store
        users.update({
            "Username": username
        }, {"$set": {"Sentence": sentence, "Tokens": num_tokens-1}
            })

        retJson = {
            "status": 200,
            "msg": "Sentence saved successfully"
        }
        return jsonify(retJson)


class Get(Resource):
    def post(self):
        postData = request.get_json()

        username = postData["username"]
        password = postData["password"]
        # verify username and pw
        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status": 302,
                "msg": "Invalid credentials"
            }
            return jsonify(retJson)

        # verify enough tokens
        num_tokens = countTokens(username)
        if not num_tokens > 0:
            retJson = {
                "status": 301,
                "msg": "Not enough tokens"
            }
            return retJson

        # Make the user
        users.update({
            "Username": username
        }, {"$set": {"Tokens": num_tokens-1}
            })

        sentence = users.find({
            "Username": username
        })[0]["Sentence"]

        retJson = {
            "status": 200,
            "msg": "Retrived successfullt",
            "sentence": sentence
        }
        return jsonify(retJson)


# Register Resources
api.add_resource(Register, "/register")
api.add_resource(Store, "/store")
api.add_resource(Get, "/get")


@app.route("/")
def hello():
    return "Hello, World!"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
