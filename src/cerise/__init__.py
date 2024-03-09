"""Cerise is a toolkit that goes over cherrypy handling many features
like mailing and authentication for Carbonlab's infrastructure.
"""

# stdlibs
from os.path import abspath, dirname
import datetime
import json

import cherrypy
import bcrypt
import jwt
from configparser import ConfigParser

# in house modules
from db import db_service as db

# OTP imports
import random as rand
import math


class Cerise:
    def __init__(self, path, configFile, debug=False):
        self.path = path
        self.debug = debug

        self.start(configFile)
        self.db = db.DB(user=self.config.get('DB', 'DB_USER'), password=self.config.get('DB', 'DB_PASSWORD'),
                   host=self.config.get('DB', 'DB_HOST'), port=int(self.config.get('DB', 'DB_PORT')), db=self.config.get('DB', 'DB_NAME'))


    #-----------------------UNIAUTH RELATED METHODS-----------------------------

    @cherrypy.expose
    def auth(self, parrain=None):
        return open(self.PATH + "/ressources/home/auth.html")

    @cherrypy.expose
    def verif(self):
        self.checkJwt(verif=True)
        return open(PATH + "/ressources/home/verif.html")

    @cherrypy.expose
    def resendVerif(self):
        user = self.getUser()
        self.sendVerification(user)


    @cherrypy.expose
    def login(self, email, password, parrain=None):
        if 'email' and 'password':
            password = password.encode('utf-8')  # converting to bytes array
            account = self.db.getUserCredentials(email)
            # If account exists in accounts table
            if account:
                msg = self.connect(account, password)
            else:
                msg = self.register(email, password, parrain)
        else:
            msg = 'please give an email and a password'

        return msg

    @cherrypy.expose
    def signup(self, code):
        user = self.getUser()
        actual = self.db.getSomething("verif_codes", user)
        if str(actual["code"]) == code and actual["expiration"] > datetime.datetime.now():
            self.db.edit("accounts", user, "verified", True)
            self.createJwt(user, True)
            return "ok"
        else:
            return "Code erroné"

    @cherrypy.expose
    def logout(self):
        token = self.getJWT()
        cookie = cherrypy.response.cookie
        cookie['JWT'] = token
        cookie['JWT']['expires'] = 0
        return 'ok'

    @cherrypy.expose
    def goodbye(self):#delete account
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        cookie = cherrypy.response.cookie
        cookie['JWT'] = token
        cookie['JWT']['expires'] = 0
        self.db.deleteSomething("accounts", info['username'])
        self.db.deleteSomething("verif_codes", info['username'])
        return 'ok'


    def createJwt(self, uid, verified):
        payload = {
            'username': uid,
            'verified': verified,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        token = jwt.encode(payload, self.config.get('security', 'SECRET_KEY'), algorithm='HS256')
        cookie = cherrypy.response.cookie
        cookie['JWT'] = token
        cookie['JWT']['httponly'] = 1
        cookie['JWT']['SameSite'] = 'Strict'
        cookie['JWT']['secure'] = 1

        cookie = cherrypy.response.cookie
        cookie['JWT'] = token
        return token

    def checkJwt(self, verif=False):
        try:
            token = self.getJWT()
        except:
            raise cherrypy.HTTPRedirect("/auth/")

        try:
            info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
            if not info['verified'] and not verif:
                raise cherrypy.HTTPRedirect("/verif/")
            elif verif and info['verified']:
                raise cherrypy.HTTPRedirect("/demo/")
        except jwt.ExpiredSignatureError:
            raise cherrypy.HTTPRedirect("/auth/")
        except jwt.DecodeError:
            raise cherrypy.HTTPError(400, 'ERROR : INVALID TOKEN')


    def getJWT(self):
        token = str(cherrypy.request.cookie['JWT']).split('JWT=')[1]
        return token

    def getUser(self):
        token = self.getJWT()
        info = jwt.decode(token, self.config.get('security', 'SECRET_KEY'), algorithms=['HS256'])
        return info['username']

    def sendVerification(self, uid, mail=''):
        if mail == '':
            mail = self.db.getUser(uid, target="email")["email"]
        OTP = self.generateOTP()
        expiration = datetime.datetime.now() + datetime.timedelta(hours=1)
        self.db.insertReplaceDict("verif_codes", {"id": uid, "code": OTP, "expiration": expiration})
        if not self.debug:
            noreply.sendConfirmation(mail, OTP)
        else:
            print(OTP)

    def generateOTP(self):
        digits = "0123456789"
        OTP = ""

        for i in range(6):
            OTP += digits[math.floor(rand.random() * 10)]

        return OTP

    def register(self, username, password, parrain):
        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password, salt)
        uid = self.db.createAccount(username, hash, parrain)
        self.createJwt(uid, False)
        self.sendVerification(uid=uid, mail=username)
        pending = self.db.getSomething('pendingmembership', username, 'email')
        if pending:
            self.db.insertDict('membership', {'account': uid, 'company': pending['company']})
            self.db.deleteSomething('pendingmembership',pending['id'])
        return "verif"

    def connect(self, account, password):
        result = bcrypt.checkpw(password, account["password"])
        if result:
            self.createJwt(account['id'], account["verified"])
            return "ok"
        else:
            return "invalid email or password"


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
            print("config read", self.path + configFile)
        except Exception:
            print("please create a config file")

    def start(self, configFile):
        self.importConf(configFile)
        print("config ", self.config.sections())

        cherrypy.config.update({'server.socket_host': self.config.get('server', 'IP'),
                                'server.socket_port': int(self.config.get('server', 'PORT')),
                                'tools.staticdir.on': True,
                                'tools.staticdir.dir': abspath(self.path + '/ressources'),
                                'error_page.404': self.path + "/ressources/404.html"})
        cherrypy.quickstart(self)
