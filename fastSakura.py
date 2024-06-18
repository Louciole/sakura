"""Sakura is an opinionated toolkit/framework that goes over fastwsgi handling many features
like mailing and authentication.
It's built to work in carbonlab's stack exclusively
"""

# stdlibs
from os.path import abspath, dirname
import datetime
import json
import inspect

import re
import fastwsgi
from configparser import ConfigParser

RE_URL = re.compile(r"[\&]")
RE_PARAM = re.compile(r"[\=]")
routes = {}


class Server:
    def __init__(self, path, configFile, noStart=False):
        print("starting Sakura server...")
        self.path = path
        self.importConf(configFile)

        if noStart:
            return

        self.onStart()

        self.start()

    def serve(func):
        def wrapper(self, start_response, *args, **kwargs):
            print("we are in the decorator", func.__name__)

            try:
                res = func(self, *args, **kwargs).encode()
                print("res =", res)
                # res=res
                headers = [('Content-Type', 'text/html')]
                start_response('200 OK', headers)
                return res
            except Exception as e:
                print("AHHH", e)
                headers = [('Content-Type', 'text/plain')]
                start_response('500 ERROR', headers)
                return ("ERROR 500 : " + str(e)).encode()

        name = func.__name__
        if func.__name__ == "index":
            name = "/"
        else:
            name = "/" + func.__name__

        routes[name] = {"params": inspect.signature(func).parameters, "target": wrapper}
        return wrapper

    def onrequest(self, environ, start_response):
        print("[INFO] Sakura - request received :'", str(environ['PATH_INFO']) + "'")
        target = environ['PATH_INFO']

        if routes.get(target):
            print("TARGET :", target, environ['PATH_INFO'])

            if environ.get('QUERY_STRING'):
                args = re.split(RE_URL, environ['QUERY_STRING'])
                return routes[target]["target"](self, start_response, args)
            else:
                return routes[target]["target"](self, start_response)

        else:
            response_headers = [('Content-Type', 'text/plain')]
            start_response("404 Not Found", response_headers)
            return "ERROR 404 : Not found".encode()


    def onLogin(self, uid):
            pass

    def onStart(self):
        pass

    @serve
    def foo(self, a, b="o_O"):
        return "foooo" + str(a)

    @serve
    def bar(self, *args, **kwargs):
        return str(*args)

    # --------------------------GENERAL USE METHODS------------------------------

    def importConf(self, configFile):
        self.config = ConfigParser()
        try:
            self.config.read(self.path + configFile)
            print("config at " + self.path + configFile + " loaded")
        except Exception:
            print("please create a config file")

    def start(self):
        fastwsgi.run(wsgi_app=self.onrequest, host=self.config.get('server', 'IP'),
                     port=int(self.config.get('server', 'PORT')))


class HTTPError(Exception):
    def __init__(error):
        print("ERROR - SAKURA", str(error))
        return "unknown error"
