import sys
from configparser import ConfigParser
from os.path import abspath, dirname
import subprocess

PATH = dirname(abspath(__file__))


class Installer:
    def __init__(self, configFile, arg="all"):
        self.importConf(configFile)
        self.uniauth = "N"
        self.name = self.config.get("server", "SERVICE_NAME").replace(" ", "_").upper()

        if arg == "all" or arg == "a":
            self.installAll()
        elif arg == "db":
            self.installDB()
        elif arg == "uniauth":
            self.installUniauth()
        elif arg == "vesta":
            self.resetVesta()
        elif arg == "reset":
            self.resetDB()
        elif arg == "service":
            self.installService()
        elif arg == "cron":
            self.setupCrons()

    def ex(self, command):
        subprocess.run(command, shell=True, check=True)

    def installDB(self):
        print("----DB----")
        self.ex("sudo -u postgres createdb " + self.config.get("DB", "DB_NAME"))
        self.ex("sudo -u postgres createuser " + self.config.get("DB", "DB_USER") + " -s --pwprompt ")

    def resetVesta(self):
        self.ex("pip uninstall vesta")
        self.ex("pip install git+https://gitlab.com/Louciole/vesta.git/")

    def installUniauth(self):
        print("----UNIAUTH----")
        while True:
            uniauth = input("Do you want to create a uniauth database? (y/n)")
            if uniauth.upper() == 'Y' or uniauth.upper() == 'N':
                self.uniauth = uniauth.upper()
                break

        if self.uniauth == 'Y':
            self.ex("sudo -u postgres createdb " + self.config.get("UNIAUTH", "DB_NAME"))

    def initDB(self):
        self.ex("python3 ./db/initDB.py " + self.uniauth)

    def resetDB(self):
        self.ex("sudo -u postgres dropdb " + self.config.get("DB", "DB_NAME"))
        self.initDB()

    def installAll(self):
        self.installNginx()
        self.installDB()
        self.installUniauth()
        self.initDB()








if len(sys.argv) > 1:
    Installer(PATH + "/server.ini", sys.argv[1])
else:
    Installer(PATH + "/server.ini")
