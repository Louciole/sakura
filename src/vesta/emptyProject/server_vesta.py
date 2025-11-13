from vesta import Server, HTTPError, HTTPRedirect

from os.path import abspath, dirname

PATH = dirname(abspath(__file__))

class App(Server):
    features = {"errors": {404: "/static/404.html"}}

    @Server.expose
    def index(self):
        return self.file(PATH + "/static/home/home.html")

    def onLogin(self, uid):
        pass

App(path=PATH, configFile="/server.ini")