from sakura import Server
import cherrypy

from os.path import abspath, dirname
PATH = dirname(abspath(__file__))

class Hello(Server):
    @cherrypy.expose
    def index(self):
        return open(PATH + "/ressources/home/home.html")


Hello(path=PATH, configFile="/server.ini")
