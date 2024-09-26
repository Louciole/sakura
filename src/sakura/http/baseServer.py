import fastwsgi
import inspect

import os
import time

import re
import urllib

#requests modules
import multipart as mp
from io import BytesIO

from configparser import ConfigParser

from sakura.http import response as Response
from sakura import HTTPError,HTTPRedirect

RE_URL = re.compile(r"[\&]")
RE_PARAM = re.compile(r"[\=]")

routes = {}
class BaseServer:
    features = {}

    def __init__(self, path, configFile, noStart=False):
        print("[INFO] starting Sakura server...")
        self.path = path

        self.importConf(configFile)

        if noStart:
            return

        self.start()

    #----------------------------HTTP SERVER------------------------------------
    def expose(func):
        def wrapper(self, *args, **kwargs):

            res = func(self, *args, **kwargs)
            # print("[DEBUG] res : ", res)

            self.response.ok()
            if res:

                return res.encode()
            else:
                return "".encode()

        name = func.__name__
        if func.__name__ == "index":
            name = "/"
        else:
            name = "/" + func.__name__

        routes[name] = {"params": inspect.signature(func).parameters, "target": wrapper}
        return wrapper

    def parseCookies(self, cookieStr):
        if not cookieStr:
            return
        cookies = {}
        for cookie in cookieStr.split(';'):
            key, value = cookie.split('=')
            cookies[key.strip()] = value
        return cookies

    def onrequest(self, environ, start_response):
        self.response = Response(start_response=start_response)
        print("[INFO] Sakura - request received :'", str(environ['PATH_INFO']) + "'")
        target = environ['PATH_INFO']

        if routes.get(target):
            self.response.cookies = self.parseCookies(environ.get('HTTP_COOKIE'))

            if environ.get('CONTENT_TYPE'):
                content_type = environ.get('CONTENT_TYPE').strip().split(";")
            else:
                content_type = ["text/html"]

            args = {}
            if environ.get('QUERY_STRING'):
                query = re.split(RE_URL, environ['QUERY_STRING'])
                for i in range(0, len(query)):
                    query[i] = re.split(RE_PARAM, query[i])
                    args[query[i][0]] = urllib.parse.unquote(query[i][1])
            if content_type[0] == "multipart/form-data":
                length = int(environ.get('CONTENT_LENGTH'))
                body = environ['wsgi.input'].read(length)
                sep = content_type[1].split("=")[1]
                body = mp.MultipartParser(BytesIO(body), sep.encode('utf-8'))
                for part in body.parts():
                    args[part.name] = part.value

            try:
                if len(args) == 0:
                    return routes[target]["target"](self)
                return routes[target]["target"](self, **args)
            except (HTTPError, HTTPRedirect):
                return self.response.encode()
            except Exception as e:
                print("[ERROR] Sakura - UNEXPECTED ERROR :", e)
                self.response.code = 500
                self.response.ok()
                self.response.content = str(e)
                return self.response.encode()
        else:
            self.response.code = 404
            self.response.ok()
            return self.response.encode()

    def onStart(self):
        pass

    #--------------------------GENERAL USE METHODS------------------------------

    def importConf(self, configFile):
        self.config = ConfigParser()
        try:
            self.config.read(self.path + configFile)
            print("[INFO] Sakura - config at " + self.path + configFile + " loaded")
        except Exception:
            print("[ERROR] Sakura - Please create a config file")

    def start(self):
        self.fileCache = {}

        if self.features.get("errors"):
            for code, page in self.features["errors"].items():
                Response.ERROR_PAGES[code] = self.path + page

        self.onStart()

        fastwsgi.server.nowait = 1
        fastwsgi.server.hook_sigint = 1

        print("[INFO] Sakura - server running on PID:", os.getpid())
        fastwsgi.server.init(app=self.onrequest, host=self.config.get('server', 'IP'),
                             port=int(self.config.get('server', 'PORT')))
        while True:
            code = fastwsgi.server.run()
            if code != 0:
                break
            time.sleep(0)
        self.close()

    def close(self):
        print("[INFO] SIGTERM/SIGINT received")
        fastwsgi.server.close()
        print("[INFO] SERVER STOPPED")
        exit()

    def file(self, path, responseFile=True):
        if responseFile:
            self.response.type = "html"
            self.response.headers = [('Content-Type', 'text/html')]
        file = self.fileCache.get(path)
        if file:
            return file
        else:
            file = open(path)
            content = file.read()
            file.close()
            self.fileCache[path] = content
            return content
