from fastSakura import Server

from os.path import abspath, dirname
PATH = dirname(abspath(__file__))

class Hello(Server):
    @Server.serve
    def index(self):
        print("IN INDEX")
        return open(PATH + "/ressources/home/home.html").read()


Hello(path=PATH, configFile="/server.ini")
