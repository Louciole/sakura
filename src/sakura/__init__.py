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
import urllib.parse
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
    def __init__(self, path, configFile, noStart=False):
        print("starting Sakura server...")
        self.path = path

        self.importConf(configFile)
        self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                        host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')),
                        db=self.config.get('DB', 'DB_NAME'))
        print("successfully connected to postgresql!")
        self.uniauth = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                             host=self.config.get('UNIAUTH', 'DB_HOST'),
                             port=int(self.config.get('UNIAUTH', 'DB_PORT')), db=self.config.get('UNIAUTH', 'DB_NAME'))
        print("successfully connected to uniauth!")

        if not self.config.getboolean("server", "DEBUG"):
            self.noreply = mailing.Mailing(self.config.get('MAILING', 'MAILING_HOST'),
                                           self.config.get('MAILING', 'MAILING_PORT'),
                                           "noreply@carbonlab.dev", self.config.get('MAILING', 'NOREPLY_PASSWORD'),
                                           self.config.get("server", "SERVICE_NAME"), self.path)
            print("successfully connected to the mailing service!")

        if noStart:
            return

        self.onStart()
        self.start()

    #----------------------------HTTP SERVER------------------------------------
    def expose(func):
        def wrapper(self, *args, **kwargs):
            res = func(self, *args, **kwargs).encode()
            # res=res
            self.response.ok()
            return res

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
                    args[query[i][0]] = query[i][1]
            if content_type[0] == "multipart/form-data":
                length = int(environ.get('CONTENT_LENGTH'))
                body = environ['wsgi.input'].read(length)
                sep = content_type[1].split("=")[1]
                body = mp.MultipartParser(BytesIO(body), sep)
                for part in body.parts():
                    args[part.name] = part.value

            try:
                if len(args) == 0:
                    return routes[target]["target"](self)
                return routes[target]["target"](self, **args)
            except (HTTPError, HTTPRedirect):
                return self.response.encode()
            except Exception as e:
                print("UNEXPECTED ERROR :", e)
                self.response.code = 500
                self.response.ok()
                self.response.content = e
                return self.response.encode()
        else:
            self.response.code = 404
            self.response.ok()
            return self.response.encode()

    #-----------------------UNIAUTH RELATED METHODS-----------------------------

    @expose
    def auth(self, parrain=None):
        return open(self.path + "/static/home/auth.html").read()

    @expose
    def verif(self):
        self.checkJwt(verif=True)
        return open(self.path + "/static/home/verif.html").read()

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
        self.response.del_cookie('JWT')
        return 'ok'

    @expose
    def goodbye(self):  #delete account
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        self.response.del_cookie('JWT')
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
            raise HTTPRedirect("/auth")
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
    CODES = {200: "200 OK", 404: "404 Not Found", 500: "500 Server Error", 302: "302 Redirect"}

    def __init__(self, start_response, code=200, type="html"):
        self.cookies = {}
        self.headers = [('Content-Type', 'text/' + type)]
        self.code = code
        self.start_response = start_response
        self.content = ""

    def ok(self):
        if self.code != 200 and self.code != 302:
            self.headers = [('Content-Type', 'text/plain')]
        self.start_response(self.CODES.get(self.code, "500 UNEXPECTED"), self.headers)

    def encode(self):
        return (self.CODES[self.code] + " " + str(self.content)).encode()

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
