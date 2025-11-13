"""
------------------------------------------------------------------------------------------------------------------------

   __.--~~.,-.__                    Welcome to VESTA
   `~-._.-(`-.__`-.
           \    `~~`        Vesta is a strongly opinionated and minimalist Framework.
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
import threading
import os
import time

import fastwsgi
import bcrypt
import jwt
from configparser import ConfigParser
import websockets

# in house modules
from vesta.db import db_service as db
from vesta.mailing import mailing_service as mailing

# OTP imports
import random as rand
import math

from vesta.http import baseServer as server
from vesta.http import error as HTTPError
from vesta.http import redirect as HTTPRedirect
from vesta.http import response as Response
server = server.BaseServer
Response = Response.Response
HTTPRedirect = HTTPRedirect.HTTPRedirect
HTTPError = HTTPError.HTTPError
from colorama import Fore, Style
from colorama import init as colorama_init
colorama_init()

class Server(server):
    features = {}

    def __init__(self, path, configFile, noStart=False):
        print(Fore.GREEN,"[INFO] starting Vesta server...")
        self.path = path

        self.importConf(configFile)
        self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                        host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')),
                        db=self.config.get('DB', 'DB_NAME'))
        print(Fore.GREEN,"[INFO] successfully connected to postgresql!")
        self.uniauth = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                             host=self.config.get('UNIAUTH', 'DB_HOST'),
                             port=int(self.config.get('UNIAUTH', 'DB_PORT')), db=self.config.get('UNIAUTH', 'DB_NAME'))
        print(Fore.GREEN,"[INFO] successfully connected to uniauth!")

        if not self.config.getboolean("server", "DEBUG"):
            self.noreply = mailing.Mailing(self.config.get('MAILING', 'MAILING_HOST'),
                                           self.config.get('MAILING', 'MAILING_PORT'),
                                           "noreply@carbonlab.dev", self.config.get('MAILING', 'NOREPLY_PASSWORD'),
                                           self.config.get("server", "SERVICE_NAME"), self.path)
            print(Fore.GREEN,"[INFO] successfully connected to the mailing service!")

        if noStart:
            return

        self.start()

    #-----------------------UNIAUTH RELATED METHODS-----------------------------

    @server.expose
    def auth(self, parrain=None, ref=None):
        return (open(self.path + "/static/home/auth.html").read() )

    @server.expose
    def reset(self, email):
        return open(self.path + "/static/home/reset.html").read()

    @server.expose
    def verif(self, ref=None):
        self.checkJwt(verif=True)
        return open(self.path + "/static/home/verif.html").read()

    @server.expose
    def resendVerif(self):
        user = self.getUser()
        self.sendVerification(user)

    @server.expose
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

    @server.expose
    def changePasswordVerif(self,mail, code, password):
        id = self.uniauth.getSomething("account", mail,"email")["id"]
        if not id :
            return "no account found for " + mail

        password = password.encode('utf-8')
        actual = self.uniauth.getSomething("reset_code", id)
        if actual and str(actual["code"]) == code and actual["expiration"] > datetime.datetime.now():
            self.changePassword(id, password)
            return "ok"
        else:
            return "Code erroné"

    @server.expose
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
            return "ok"
        else:
            return "no account found for " + email


    @server.expose
    def signup(self, code):
        user = self.getUser()
        actual = self.uniauth.getSomething("verif_code", user)
        if str(actual["code"]) == code and actual["expiration"] > datetime.datetime.now():
            self.uniauth.edit("account", user, "verified", True)
            self.createJwt(user, True)
            self.onLogin(user)
            return "ok"
        else:
            return "Code erroné"

    @server.expose
    def logout(self):
        token = self.getJWT()
        self.response.del_cookie('JWT')
        self.response.del_cookie('auth')
        raise HTTPRedirect(self.response, "/auth")

    @server.expose
    def goodbye(self):  #delete account
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        self.response.del_cookie('JWT')
        self.response.del_cookie('auth')
        self.uniauth.deleteSomething("account", info['username'])
        self.uniauth.deleteSomething("verif_code", info['username'])
        return 'ok'

    def createJwt(self, uid, verified):
        payload = {
            'username': uid,
            'verified': verified,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        token = jwt.encode(payload, self.config.get('security', 'SECRET_KEY'), algorithm='HS256')

        self.response.set_cookie('JWT', token, exp={"value": 100, "unit": "days"}, httponly=True, samesite='Strict',
                                 secure=True)
        self.response.set_cookie('auth', "true", exp={"value": 100, "unit": "days"}, samesite='Strict')

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
        except (jwt.ExpiredSignatureError, jwt.DecodeError):
            self.logout()
        return info

    def getJWT(self):
        token = self.response.cookies['JWT']
        return token

    def getUser(self):
        info = self.checkJwt()
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
        digits = "0123456789"
        OTP = ""

        for i in range(n):
            OTP += digits[math.floor(rand.random() * 10)]

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
            print(Fore.GREEN,"[INFO] Vesta - config at " + self.path + configFile + " loaded")
        except Exception:
            print(Fore.RED,"[ERROR] Vesta - Please create a config file")

    def start(self):
        self.fileCache = {}

        if self.features.get("websockets"):
            self.id = 1  # TODO give a different id to each server to allow them to contact eachother
            self.pool = {}
            self.waiting_clients = {}
            self.currentWaiting = 0
            self.stop_event = asyncio.Event()
            websocket_thread = threading.Thread(target=self.startWebSockets)
            websocket_thread.start()
            print(Fore.GREEN,"[INFO] Vesta - WS server started")

        if self.features.get("errors"):
            for code, page in self.features["errors"].items():
                Response.ERROR_PAGES[code] = self.path + page

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
        if self.features.get("websockets"):
            self.closeWebSockets()

        self.clean()
        print(Fore.GREEN,"[INFO] SERVER STOPPED")
        exit()

    def startWebSockets(self):
        server = threading.Thread(target=self.runWebsockets, daemon=True)
        server.start()

    async def handle_message(self,websocket):
        pass

    def runWebsockets(self):
        """
        Asynchronously runs the WebSocket server.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def _run_server():
                async with websockets.serve(
                        self.handle_message,
                        self.config.get("server", "IP"),
                        int(self.config.get("NOTIFICATION", "PORT"))
                ):
                    await asyncio.Future()

            loop.run_until_complete(_run_server())
            loop.run_forever()
            loop.close()

        except Exception as e:
            print(Fore.RED,"[ERROR] Vesta - exception in ws server:", e)

    def file(self,path):
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
        print(Fore.GREEN,"[INFO] WS server closed")

    def clean(self):
        pass

    def stop(self):
        fastwsgi.server.close()
        for client, ws in self.pool.items():
            self.db.deleteSomething("active_client", client)
        print(Fore.GREEN,"[INFO] cleaned database")

    # --------------------------------WEBSOCKETS--------------------------------
    @server.expose
    def config(self):
        if not self.features.get("websockets"):
            raise HTTPError(self.response, 404)

        if self.config.getboolean("server", "DEBUG"):
            url = self.config.get("NOTIFICATION", "DEBUG_URL")
        else:
            url = self.config.get("NOTIFICATION", "URL")

        doc= f"""const WEBSOCKETS = "{url}";\n """ + "export {WEBSOCKETS}"

        self.response.type = "application/javascript"
        self.response.headers = [('Content-Type', 'application/javascript')]
        return doc


    @server.expose
    def authWS(self, connectionId):
        account_id = self.getUser()
        if int(self.waiting_clients[int(connectionId)]["uid"]) != account_id:
            raise HTTPError(self.response, 403)

        connection = self.db.insertDict("active_client", {"userid": account_id, "server": self.id}, True)
        self.pool[connection] = self.waiting_clients[int(connectionId)]["connection"]
        del self.waiting_clients[int(connectionId)]
        self.onWSAuth(account_id)
        return str(connection)

    def onWSAuth(self,uid):
        pass

    async def sendNotificationAsync(self, account, content, exclude=None):
        message = {"type": "notif", "content": content}

        clients = self.db.getAll("active_client", account, "userid")
        clients_to_remove = []

        for client in clients:
            #TODO handle multi server
            if self.pool.get(client["id"]):
                websocket = self.pool[client["id"]]

                if exclude and websocket == exclude:
                    continue

                try:
                    if hasattr(websocket, 'closed') and websocket.closed:
                        print(f"[INFO] Client {client['id']} already closed (closed)")
                        clients_to_remove.append(client["id"])
                        continue
                    elif hasattr(websocket, 'state') and websocket.state.name in ['CLOSED', 'CLOSING']:
                        print(f"[INFO] Client {client['id']} already closed (state: {websocket.state.name})")
                        clients_to_remove.append(client["id"])
                        continue

                    await websocket.send(json.dumps(message))
                except Exception as e:
                    clients_to_remove.append(client["id"])
            else:
                clients_to_remove.append(client["id"])

        for client_id in clients_to_remove:
            print(f"[INFO] Cleaning client {client_id}")
            if client_id in self.pool:
                del self.pool[client_id]
            self.db.deleteSomething("active_client", client_id)


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
                    print(Fore.RED,"[ERROR] Vesta - exception sending a message '", message,"' on a ws", e)
                    del self.pool[client["id"]]
                    self.db.deleteSomething("active_client", client["id"])
            else:
                self.db.deleteSomething("active_client", client["id"])
