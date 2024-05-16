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

RE_URL= re.compile(r"[\?\&]")
routes={}
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
        def wrapper(self,*args,**kwargs):
            print("we are in the decorator")
            headers = [('Content-Type', 'text/plain')]
            try : 
                res = func()
                start_response('200 OK', headers)
                return res
            except Exception as e:
                start_response('502 ERROR', headers)
                return e
        name = func.__name__
        if func.__name__ != "index":
            name = "/"
    
        routes[name]={"params":inspect.signature(func).parameters,"target":wrapper}
        return wrapper
    
    def onrequest(self, environ, start_response):
        print("[INFO] Sakura - request received :'", str(environ['PATH_INFO'])+"'")
        target = re.split(RE_URL, environ['PATH_INFO'])
        print(target)
        if routes.get(target[0]):
            
            return routes[target[0]]["target"]()
        else:
            start_response("404 Error")
            return ['']



    def onLogin(self, uid):
        pass

    def onStart(self):
        pass

    @serve
    def foo(self,a,b="o_O"):
        pass

    @serve
    def bar(self,*args,**kwargs):
        pass

    #--------------------------GENERAL USE METHODS------------------------------

    def importConf(self, configFile):
        self.config = ConfigParser()
        try:
            self.config.read(self.path + configFile)
            print("config at " + self.path + configFile + " loaded")
        except Exception:
            print("please create a config file")

    def start(self):
        fastwsgi.run(wsgi_app=self.onrequest, host=self.config.get('server', 'IP'), port=int(self.config.get('server', 'PORT')))

class HTTPError(Exception):
    def __init__(error):
        print("ERROR - SAKURA",str(error))
        return "unknown error"
