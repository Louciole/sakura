import cerise
import cherrypy


class Disclone(cerise):
    @cherrypy.expose
    def index(self):
        return open(PATH + "/page.html")


Disclone.start("server.ini")