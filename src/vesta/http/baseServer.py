import fastwsgi
import inspect

import os
import time
import json
import hashlib
import base64

import re
import urllib

#requests modules
import multipart as mp
from io import BytesIO

from configparser import ConfigParser

from vesta.http import response
from vesta.http import error
from vesta.http import redirect
from vesta.db import db_service as db
Response = response.Response
HTTPRedirect = redirect.HTTPRedirect
HTTPError = error.HTTPError

RE_URL = re.compile(r"[\&]")
RE_PARAM = re.compile(r"[\=]")

routes = {}

from colorama import Fore, Style
from colorama import init as colorama_init
colorama_init()

class BaseServer:
    features = {}

    def __init__(self, path, configFile, noStart=False):
        print(Fore.GREEN,"[INFO] starting Vesta server...")
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
        elif func.__name__ == "default":
            name = "default"
        else:
            name = "/" + func.__name__

        routes[name] = {"params": inspect.signature(func).parameters, "target": wrapper}
        return wrapper

    def saveFile(self, content, name="",ext=None, category=None):
        content = content.split(",")
        extension = content[0].split("/")[1].split(";")[0]
        content = base64.b64decode(content[1])

        if not name :
            hash_object = hashlib.sha256(content)
            hex_dig = hash_object.hexdigest()

            name = hex_dig

        prefix = self.path + "/static/attachments/"
        if category:
            name = category + "/"  + name
        if ext :
            name = name + "." + ext

        with open(prefix+name, 'wb') as f:
            f.write(content)
        return name

    def parseCookies(self, cookieStr):
        if not cookieStr:
            return
        cookies = {}
        for cookie in cookieStr.split(';'):
            key, value = cookie.split('=')
            cookies[key.strip()] = value
        return cookies


    def parseRequest(self,environ):
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
        if content_type[0] == "application/json":
            length = int(environ.get('CONTENT_LENGTH'))
            body = environ['wsgi.input'].read(length)
            body = json.loads(body)
            for key in body:
                args[key] = body[key]

        return args


    def tryDefault(self, environ, target):
        print(Fore.WHITE,"[INFO] Vesta - using default route")

        args = self.parseRequest(environ)
        args["target"] = target
        try:
            return routes["default"]["target"](self, **args)
        except (HTTPError, HTTPRedirect):
            return self.response.encode()
        except Exception as e:
            return self.handleUnexpected(e)


    def onrequest(self, environ, start_response):
        self.response = Response(start_response=start_response)
        print(Fore.WHITE,"[INFO] Vesta - request received :'", str(environ['PATH_INFO']) + "'" + " with "+ str(environ.get('QUERY_STRING')))
        target = environ['PATH_INFO']

        if routes.get(target):
            args = self.parseRequest(environ)

            try:
                if len(args) == 0:
                    return routes[target]["target"](self)
                return routes[target]["target"](self, **args)
            except (HTTPError, HTTPRedirect):
                return self.response.encode()
            except Exception as e:
               return self.handleUnexpected(e)
        else:
            if routes.get("default"):
                return self.tryDefault(environ, target)
            self.response.code = 404
            self.response.ok()
            return self.response.encode()

    def handleUnexpected(self, e):
        print(Fore.RED,"[ERROR] Vesta - UNEXPECTED ERROR :", e)
        self.response.code = 500
        self.response.ok()
        self.response.content = str(e)
        tb = e.__traceback__
        while tb is not None:
            frame = tb.tb_frame
            lineno = tb.tb_lineno
            filename = frame.f_code.co_filename
            funcname = frame.f_code.co_name
            print(f'  File "{filename}", line {lineno}, in {funcname}')
            if self.features.get("debug"):
                self.response.content += f'  File "{filename}", line {lineno}, in {funcname}'
            tb = tb.tb_next
        return self.response.encode()

    def onStart(self):
        pass

    #--------------------------GENERAL USE METHODS------------------------------

    def importConf(self, configFile):
        self.config = ConfigParser()
        try:
            self.config.read(self.path + configFile)
            print(Fore.GREEN,"[INFO] Vesta - config at " + self.path + configFile + " loaded")
        except Exception:
            print(Fore.RED,"[ERROR] Vesta - Please create a config file")

    def start(self):
        self.fileCache = {}

        if self.features.get("errors"):
            for code, page in self.features["errors"].items():
                Response.ERROR_PAGES[code] = self.path + page

        if self.features.get("orm") == True:
            self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                            host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')),
                            db=self.config.get('DB', 'DB_NAME'))


        self.onStart()

        fastwsgi.server.nowait = 1
        fastwsgi.server.hook_sigint = 1

        print(Fore.GREEN,"[INFO] Vesta - server running on PID:", os.getpid())
        fastwsgi.server.init(app=self.onrequest, host=self.config.get('server', 'IP'),
                             port=int(self.config.get('server', 'PORT')))
        while True:
            code = fastwsgi.server.run()
            if code != 0:
                break
            time.sleep(0)
        self.close()

    def close(self):
        print(Fore.GREEN,"[INFO] SIGTERM/SIGINT received")
        fastwsgi.server.close()
        print(Fore.GREEN,"[INFO] SERVER STOPPED")
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

    def start_ORM(self):
        if self.features.get("orm") == True:
            self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                            host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')),
                            db=self.config.get('DB', 'DB_NAME'))
        else:
            raise Exception("ORM not enabled")