from flask import Flask

app = Flask(__name__)

from .core import app_setup
