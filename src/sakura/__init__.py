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
from os.path import abspath, dirname
import datetime
import json
import inspect

import re
import fastwsgi
import bcrypt
import jwt
from configparser import ConfigParser

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
    def __init__(self, path, configFile, noStart=False):
        print("starting Sakura server...")
        self.path = path

        self.importConf(configFile)
        self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                        host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')), db=self.config.get('DB', 'DB_NAME'))
        print("successfully connected to postgresql!")
        self.uniauth = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                             host=self.config.get('UNIAUTH', 'DB_HOST'), port=int(self.config.get('UNIAUTH', 'DB_PORT')), db=self.config.get('UNIAUTH', 'DB_NAME'))
        print("successfully connected to uniauth!")

        if not self.config.getboolean("server", "DEBUG"):
            self.noreply = mailing.Mailing(self.config.get('MAILING', 'MAILING_HOST'), self.config.get('MAILING', 'MAILING_PORT'),
                                           "noreply@carbonlab.dev", self.config.get('MAILING', 'NOREPLY_PASSWORD'),
                                           self.config.get("server", "SERVICE_NAME"), self.path)
            print("successfully connected to the mailing service!")

        if noStart:
            return

        self.onStart()

        self.start()


    #----------------------------HTTP SERVER------------------------------------
    def expose(func):
        def wrapper(self, response, *args, **kwargs):
            print("we are in the decorator", func.__name__)

            try:
                res = func(self, *args, **kwargs).encode()
                print("res =", res)
                # res=res
                response.ok()
                return res
            except Exception as e:
                print("AHHH", e)
                response.code=500
                response.content=e
                return str(response)

        name = func.__name__
        if func.__name__ == "index":
            name = "/"
        else:
            name = "/" + func.__name__

        routes[name] = {"params": inspect.signature(func).parameters, "target": wrapper}
        return wrapper

    def onrequest(self, environ, start_response):
        response = Response(start_response=start_response)
        print("[INFO] Sakura - request received :'", str(environ['PATH_INFO']) + "'",str(start_response))
        target = environ['PATH_INFO']

        if routes.get(target):
            print("TARGET :", target, environ['PATH_INFO'])

            if environ.get('QUERY_STRING'):
                args = re.split(RE_URL, environ['QUERY_STRING'])
                return routes[target]["target"](self, response, args)
            else:
                return routes[target]["target"](self, response)

        else:
            response.code=404
            return str(response)



    #-----------------------UNIAUTH RELATED METHODS-----------------------------

    @expose
    def auth(self, parrain=None):
        return open(self.path + "/ressources/home/auth.html")

    @expose
    def verif(self):
        self.checkJwt(verif=True)
        return open(self.path + "/ressources/home/verif.html")

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

    @expose
    def logout(self):
        token = self.getJWT()
        cookies = response.cookies
        cookies['JWT'] = token
        cookies['JWT']['expires'] = 0
        return 'ok'

    @expose
    def goodbye(self):#delete account
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        cookie = response.cookie
        cookie['JWT'] = token
        cookie['JWT']['expires'] = 0
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
        cookie = response.cookie
        cookie['JWT'] = token
        cookie['JWT']['httponly'] = 1
        cookie['JWT']['SameSite'] = 'Strict'
        cookie['JWT']['secure'] = 1

        cookie = response.cookie
        cookie['JWT'] = token
        return token

    def checkJwt(self, verif=False):
        try:
            token = self.getJWT()
        except:
            raise HTTPRedirect("/auth/")

        try:
            info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
            if not info['verified'] and not verif:
                raise HTTPRedirect("/verif/")
            elif verif and info['verified']:
                raise HTTPRedirect(self.config.get("server", "DEFAULT_ENDPOINT"))
        except jwt.ExpiredSignatureError:
            raise HTTPRedirect("/auth/")
        except jwt.DecodeError:
            raise HTTPError(400, 'ERROR : INVALID TOKEN')


    def getJWT(self):
        token = str(request.cookie['JWT']).split('JWT=')[1]
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
            print("OTP : ",OTP)

    def generateOTP(self):
        digits = "0123456789"
        OTP = ""

        for i in range(6):
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
            print("config at " + self.path + configFile + " loaded")
        except Exception:
            print("please create a config file")

    def start(self):
        fastwsgi.run(wsgi_app=self.onrequest, host=self.config.get('server', 'IP'),
                     port=int(self.config.get('server', 'PORT')))
        #TODO add 404 page

class Response:
    CODES = {200:"200 OK",404:"404 Not Found",500:"500 Server Error"}

    def __init__(self, start_response ,code=200, type="html"):
        self.cookies = {}
        self.headers = [('Content-Type', 'text/'+type)]
        self.code = code
        self.start_response = start_response
        self.content=""

    def ok(self):
        self.start_response(self.CODES[self.code], self.headers)

    def __str__(self):
        if self.code != 200:
            self.headers=[('Content-Type', 'text/plain')]
        return (self.CODES[self.code] + str(self.content)).encode()

    def set_cookie(self, path=None, path_header=None, name='session_id',
                   timeout=60, domain=None, secure=False, httponly=False):
        """Set a response cookie for the client.

        path
            the 'path' value to stick in the response cookie metadata.

        path_header
            if 'path' is None (the default), then the response
            cookie 'path' will be pulled from self.headers[path_header].

        name
            the name of the cookie.

        timeout
            the expiration timeout for the cookie. If 0 or other boolean
            False, no 'expires' param will be set, and the cookie will be a
            "session cookie" which expires when the browser is closed.

        domain
            the cookie domain.

        secure
            if False (the default) the cookie 'secure' value will not
            be set. If True, the cookie 'secure' value will be set (to 1).

        httponly
            If False (the default) the cookie 'httponly' value will not be set.
            If True, the cookie 'httponly' value will be set (to 1).

        """
        #cookie_value = # Generate or retrieve the cookie value here

        # Determine cookie path
        if path is None:
            path = self.headers.get(path_header, '/') if path_header else '/'

        # Calculate expiration time
        expires = None
        if timeout:
            expires = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
            expires = expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT")

        # Construct cookie string
        # cookie_parts = [f"{name}={cookie_value}"]
        cookie_parts = []
        if expires:
            cookie_parts.append(f"Expires={expires}")
        if path:
            cookie_parts.append(f"Path={path}")
        if domain:
            cookie_parts.append(f"Domain={domain}")
        if secure:
            cookie_parts.append("Secure")
        if httponly:
            cookie_parts.append("HttpOnly")
        cookie_string = "; ".join(cookie_parts)

        # Add cookie to headers
        self.headers.append(('Set-Cookie', cookie_string))

class HTTPError(Exception):
    def __init__(error):
        print("ERROR - SAKURA", str(error))
        return "unknown error"

class HTTPRedirect:
    def __init__(self,target):
        pass
