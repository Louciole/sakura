"""
------------------------------------------------------------------------------------------------------------------------

   __.--~~.,-.__                    Welcome to SAKURA
   `~-._.-(`-.__`-.
           \    `~~`        Sakura is a strongly opinionated and minimalist Framework.
      .--./ \                   It bundles a lot of different features:
     /#   \  \.--.              - a http server
     \    /  /#   \             - a websocket server
      '--'   \    /             - a mailing server
              '--'              - some tooling
                                - an HTML templating library
                                - a reactive frontend library
                                - a unique authentification system called uniauth (think google account)

________________________________________________________________________________________________________________________
"""

# stdlibs
import datetime
import json
import inspect
import asyncio
import secrets
import threading
import os
import time

import re
import urllib

import fastwsgi
import bcrypt
import jwt
from configparser import ConfigParser
import websockets

#requests modules
import multipart as mp
from io import BytesIO

# in house modules
from sakura.db import db_service as db
from sakura.mailing import mailing_service as mailing

# OTP imports
import random as rand
import math

RE_URL = re.compile(r"[\&]")
RE_PARAM = re.compile(r"[\=]")
routes = {}


class Server:
    features = {}

    def __init__(self, path, configFile, noStart=False):
        print("[INFO] starting Sakura server...")
        self.path = path

        self.importConf(configFile)
        self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                        host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')),
                        db=self.config.get('DB', 'DB_NAME'))
        print("[INFO] successfully connected to postgresql!")
        self.uniauth = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                             host=self.config.get('UNIAUTH', 'DB_HOST'),
                             port=int(self.config.get('UNIAUTH', 'DB_PORT')), db=self.config.get('UNIAUTH', 'DB_NAME'))
        print("[INFO] successfully connected to uniauth!")

        if not self.config.getboolean("server", "DEBUG"):
            self.noreply = mailing.Mailing(self.config.get('MAILING', 'MAILING_HOST'),
                                           self.config.get('MAILING', 'MAILING_PORT'),
                                           "noreply@carbonlab.dev", self.config.get('MAILING', 'NOREPLY_PASSWORD'),
                                           self.config.get("server", "SERVICE_NAME"), self.path)
            print("[INFO] successfully connected to the mailing service!")

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

    #-----------------------UNIAUTH RELATED METHODS-----------------------------

    @expose
    def auth(self, parrain=None):
        return self.file(self.path + "/static/home/auth.html")

    @expose
    def reset(self, email):
        return self.file(self.path + "/static/home/reset.html")

    @expose
    def verif(self):
        self.checkJwt(verif=True)
        return self.file(self.path + "/static/home/verif.html")

    @expose
    def resendVerif(self):
        user = self.getUser()
        self.sendVerification(user)

    @expose
    def login(self, email, password, parrain=None):
        if 'email' and 'password':
            password = password.encode('utf-8')  # converting to bytes array
            account = self.uniauth.getUserCredentials(email)
            # If account exists in accounts table
            if account:
                msg = self.connect(account, password)
            else:
                msg = self.register(email, password, parrain)
        else:
            msg = 'please give an email and a password'

        return msg

    @expose
    def changePasswordVerif(self,mail, code, password):
        id = self.uniauth.getSomething("account", mail,"email")["id"]
        if not id :
            return "no account found for " + mail

        password = password.encode('utf-8')
        actual = self.uniauth.getSomething("reset_code", id)
        if actual and str(actual["code"]) == code and actual["expiration"] > datetime.datetime.now():
            self.changePassword(id, password)
            raise HTTPRedirect(self.response, "/auth")
        else:
            raise HTTPError(self.response, 401, 'Code erroné')

    @expose
    def passwordReset(self, email):
        account = self.uniauth.getUserCredentials(email)
        # If account exists in accounts table
        if account:
            OTP = self.generateOTP(12)
            expiration = datetime.datetime.now() + datetime.timedelta(hours=1)
            self.uniauth.insertReplaceDict("reset_code", {"id": account["id"], "code": OTP, "expiration": expiration})
            if not self.config.getboolean("server", "DEBUG"):
                self.noreply.sendTemplate('mailReset.html', email, "Reset your password","Your reset code: "+OTP, OTP)
            else:
                print("RESET OTP : ", OTP)
            raise HTTPRedirect(self.response, "/reset?email="+email)
        else:
            raise HTTPError(self.response, 401, 'no account found for ' + email)

    @expose
    def signup(self, code):
        user = self.getUser()
        actual = self.uniauth.getSomething("verif_code", user)
        if str(actual["code"]) == code and actual["expiration"] > datetime.datetime.now():
            self.uniauth.edit("account", user, "verified", True)
            self.createJwt(user, True)
            self.onLogin(user)
            raise HTTPRedirect(self.response, "/channels")
        else:
            raise HTTPError(self.response, 401, 'Code erroné')

    @expose
    def logout(self):
        token = self.getJWT()
        self.response.del_cookie('JWT')
        raise HTTPRedirect(self.response, "/auth")

    @expose
    def goodbye(self):  #delete account
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        self.response.del_cookie('JWT')
        self.uniauth.deleteSomething("account", info['username'])
        self.uniauth.deleteSomething("verif_code", info['username'])
        raise HTTPRedirect(self.response, "/auth")

    def createJwt(self, uid, verified):
        payload = {
            'username': uid,
            'verified': verified,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }
        token = jwt.encode(payload, self.config.get('security', 'SECRET_KEY'), algorithm='HS256')

        self.response.set_cookie('JWT', token, exp={"value": 15, "unit": "minutes"}, httponly=True, samesite='Strict',
                                 secure=True)

        return token

    def checkJwt(self, verif=False):
        try:
            token = self.getJWT()
        except:
            raise HTTPRedirect(self.response, "/auth")

        try:
            info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
            if not info['verified'] and not verif:
                raise HTTPRedirect(self.response, "/verif")
            elif verif and info['verified']:
                raise HTTPRedirect(self.response, self.config.get("server", "DEFAULT_ENDPOINT"))
        except jwt.ExpiredSignatureError:
            raise HTTPRedirect(self.response,"/auth")
        except jwt.DecodeError:
            raise HTTPError(self.response, 400, 'ERROR : INVALID TOKEN')

    def getJWT(self):
        token = self.response.cookies['JWT']
        return token

    def getUser(self):
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        return info['username']

    def sendVerification(self, uid, mail=''):
        if mail == '':
            mail = self.uniauth.getUser(uid, target="email")["email"]
        OTP = self.generateOTP()
        expiration = datetime.datetime.now() + datetime.timedelta(hours=1)
        self.uniauth.insertReplaceDict("verif_code", {"id": uid, "code": OTP, "expiration": expiration})
        if not self.config.getboolean("server", "DEBUG"):
            self.noreply.sendConfirmation(mail, OTP)
        else:
            print("OTP : ", OTP)

    def generateOTP(self,n=6):
        OTP = secrets.randbelow(10 ** n)
        return OTP

    def register(self, username, password, parrain):
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password, salt)
        uid = self.uniauth.createAccount(username, hash, parrain)
        self.createJwt(uid, False)
        self.sendVerification(uid=uid, mail=username)
        pending = self.uniauth.getSomething('pendingmembership', username, 'email')
        if pending:
            self.uniauth.insertDict('membership', {'account': uid, 'company': pending['company']})
            self.uniauth.deleteSomething('pendingmembership', pending['id'])
        return "verif"

    def changePassword(self, uid, password):
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password, salt)
        self.uniauth.edit("account",uid, 'password', hash)

    def connect(self, account, password):
        result = bcrypt.checkpw(password, account["password"])
        if result:
            self.createJwt(account['id'], account["verified"])
            self.onLogin(account['id'])
            return "ok"
        else:
            return "invalid email or password"

    def onLogin(self, uid):
        pass

    def onStart(self):
        pass

    #--------------------------GENERAL USE METHODS------------------------------

    def parseAcceptLanguage(self, acceptLanguage):
        languages = acceptLanguage.split(",")
        locale_q_pairs = []

        for language in languages:
            if language.split(";")[0] == language:
                # no q => q = 1
                locale_q_pairs.append((language.strip(), "1"))
            else:
                locale = language.split(";")[0].strip()
                q = language.split(";")[1].split("=")[1]
                locale_q_pairs.append((locale, q))

        return locale_q_pairs

    def importConf(self, configFile):
        self.config = ConfigParser()
        try:
            self.config.read(self.path + configFile)
            print("[INFO] Sakura - config at " + self.path + configFile + " loaded")
        except Exception:
            print("[ERROR] Sakura - Please create a config file")

    def start(self):
        self.fileCache = {}

        if self.features.get("websockets"):
            self.id = 1  # TODO give a different id to each server to allow them to contact eachother
            self.pool = {}
            self.waiting_clients = {}
            self.currentWaiting = 0
            self.stop_event = asyncio.Event()
            websocket_thread = threading.Thread(target=self.runWebsockets, daemon=True)
            websocket_thread.start()
            print("[INFO] Sakura - WS server started")

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
        if self.features.get("websockets"):
            self.closeWebSockets()

        self.clean()
        print("[INFO] SERVER STOPPED")
        exit()

    async def handle_message(self,websocket):
        pass

    def runWebsockets(self):
        try :
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ws_server = websockets.serve(self.handle_message, self.config.get("server", "IP"),
                                         int(self.config.get("NOTIFICATION", "PORT")))

            loop.run_until_complete(ws_server)
            loop.run_forever() # this is missing
            loop.close()

        except Exception as e:
            print("[ERROR] Sakura - exception in ws server", e)

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

    def closeWebSockets(self):
        for client, ws in self.pool.items():
            # Close the websocket connection
            asyncio.run_coroutine_threadsafe(ws.close(), asyncio.get_event_loop())
        self.stop_event.set()
        print("[INFO] WS server closed")

    def clean(self):
        pass

    def stop(self):
        fastwsgi.server.close()
        for client, ws in self.pool.items():
            self.db.deleteSomething("active_client", client)
        print("[INFO] cleaned database")

    # --------------------------------WEBSOCKETS--------------------------------

    @expose
    def authWS(self, connectionId):
        account_id = self.getUser()
        if self.waiting_clients[int(connectionId)]["uid"] != account_id:
            return "forbidden"

        connection = self.db.insertDict("active_client", {"userid": account_id, "server": self.id}, True)
        self.pool[connection] = self.waiting_clients[int(connectionId)]["connection"]
        del self.waiting_clients[int(connectionId)]
        self.onWSAuth(account_id)
        return str(connection)

    def onWSAuth(self,uid):
        pass

    async def sendNotificationAsync(self, account, content):
        message = {"type": "notif", "content": content}

        clients = self.db.getAll("active_client", account, "userid")
        for client in clients:
            #TODO handle multi server
            if self.pool.get(client["id"]):
                websocket = self.pool[client["id"]]
                try:
                    await websocket.send(json.dumps(message))
                except Exception as e:
                    print("[ERROR] Sakura - exception sending a message on a ws", e)
                    del self.pool[client["id"]]
                    self.db.deleteSomething("active_client", client["id"])
            else:
                self.db.deleteSomething("active_client", client["id"])

    def checkWSAuth(self, ws, clientID):
        if self.pool.get(clientID) == ws:
            return True
        return False

    def sendNotification(self, account, content):
        message = {"type": "notif", "content": content}

        async def ws_send(message):
            await websocket.send(message)

        clients = self.db.getAll("active_client", account, "userid")
        for client in clients:
            #TODO handle multi server
            if self.pool.get(client["id"]):
                websocket = self.pool[client["id"]]
                try:
                    asyncio.run(ws_send(json.dumps(message)))
                except Exception as e:
                    print("[ERROR] Sakura - exception sending a message on a ws", e)
                    del self.pool[client["id"]]
                    self.db.deleteSomething("active_client", client["id"])
            else:
                self.db.deleteSomething("active_client", client["id"])


class Response:
    CODES = {200: "200 OK", 404: "404 Not Found", 500: "500 Server Error", 302: "302 Redirect"}
    ERROR_PAGES = {}
    fileCache = {}

    def __init__(self, start_response, code=200, type="plain"):
        self.cookies = {}
        self.type = type
        self.headers = [('Content-Type', 'text/' + type),('Cache-Control', 'no-cache')]
        self.code = code
        self.start_response = start_response
        self.content = ""

    def ok(self):
        if self.code in self.ERROR_PAGES.keys():
            self.content = self.file(self.ERROR_PAGES[self.code])

        self.start_response(self.CODES.get(self.code, "500 UNEXPECTED"), self.headers)

    def file(self,path):
        #FIXME duplicate with server.file() should find a way to unify them
        self.type = "html"
        self.headers = [('Content-Type', 'text/html')]
        file = self.fileCache.get(path)
        if file:
            return file
        else:
            file = open(path)
            content = file.read()
            file.close()
            self.fileCache[path] = content
            return content

    def encode(self):
        # print("[INFO] encoding response : ", self.content)

        if self.type == "plain":
            return (self.CODES[self.code] + " " + self.content).encode()
        return str(self.content).encode()

    def set_cookie(self, name, value, exp=None, samesite=None, secure=False, httponly=False):
        """Set a response cookie for the client.
        name
            the name of the cookie.

        exp
            the expiration timeout for the cookie. If 0 or other boolean
            False, no 'expires' param will be set, and the cookie will be a
            "session cookie" which expires when the browser is closed.

        samesite
            The 'SameSite' attribute of the cookie. If None (the default)
            the cookie 'samesite' value will not be set. If 'Strict' or
            'Lax', the cookie 'samesite' value will be set to the given value.

        secure
            if False (the default) the cookie 'secure' value will not
            be set. If True, the cookie 'secure' value will be set (to 1).

        httponly
            If False (the default) the cookie 'httponly' value will not be set.
            If True, the cookie 'httponly' value will be set (to 1).

        """

        # Calculate expiration time
        expires = None
        if exp:
            if exp['unit'] == "days":
                expires = datetime.datetime.now() + datetime.timedelta(days=exp['value'])
            elif exp['unit'] == "minutes":
                expires = datetime.datetime.now() + datetime.timedelta(minutes=exp['value'])
            expires = expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT")

        # Construct cookie string
        cookie_parts = [f"{name}={value}"]
        if expires:
            cookie_parts.append(f"Expires={expires}")
        if samesite:
            cookie_parts.append(f"SameSite={samesite}")
        if secure:
            cookie_parts.append("Secure")
        if httponly:
            cookie_parts.append("HttpOnly")
        cookie_string = "; ".join(cookie_parts)

        # Add cookie to headers
        self.headers.append(('Set-Cookie', cookie_string))

    def del_cookie(self, name):
        self.set_cookie(name, "", exp={"value": 0, "unit": "days"})


class HTTPError(Exception):
    def __init__(self, response, code=500, message="Unexpected"):
        response.code = code
        response.ok()
        response.content = message


class HTTPRedirect(Exception):
    def __init__(self, response, target):
        response.code = 302
        response.headers.append(('Location', target))
        response.ok()
