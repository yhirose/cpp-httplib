from flask import Flask
app = Flask(__name__)

import logging
logging.getLogger('werkzeug').disabled = True

@app.route('/')
def hello_world():
    return 'Hello, World!'
