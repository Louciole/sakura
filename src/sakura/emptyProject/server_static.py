from sakura.http import baseServer

from os.path import abspath, dirname

PATH = dirname(abspath(__file__))
server = baseServer.BaseServer

class App(server):
    features = {}

    @server.expose
    def index(self, *args, **kwargs):
        return self.file(PATH + "/static/index.html")

App(path=PATH, configFile="/server.ini")