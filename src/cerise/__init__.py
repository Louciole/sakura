"""Cerise is a toolkit that goes over cherrypy handling many features
like mailing and authentication for Carbonlab's infrastructure.
"""

# stdlibs
from os.path import abspath, dirname

import cherrypy
from configparser import ConfigParser

# in house modules


# OTP imports
import random as rand
import math


class Cerise:
    def __init__(self, path, configFile):
        self.path = path
        self.start(configFile)

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

    def generateOTP(self):
        digits = "0123456789"
        OTP = ""

        for i in range(6):
            OTP += digits[math.floor(rand.random() * 10)]

        return OTP

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
