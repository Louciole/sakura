import cerise
import cherrypy


class Disclone(cerise):
    @cherrypy.expose
    def index(self):
        return open(PATH + "/ressources/home/home.html")


Disclone.start("server.ini")