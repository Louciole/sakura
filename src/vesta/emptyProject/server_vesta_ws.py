from vesta import Server, HTTPError, HTTPRedirect

from os.path import abspath, dirname
import json

# websockets imports
import asyncio
import websockets
import threading

PATH = dirname(abspath(__file__))

class App(Server):
    features = {"websockets": True, "errors": {404: "/static/404.html"}}
    clients = []

    @Server.expose
    def index(self):
        return self.file(PATH + "/static/home/home.html")

    def onLogin(self, uid):
        pass

    def clean(self):
        for client, ws in self.pool.items():
            self.db.deleteSomething("active_client",client)

    # --------------------------------WEBSOCKETS--------------------------------

    async def handle_message(self, websocket):
        self.clients.append(websocket)
        self.calls = {}

        async for message in websocket:
            data = json.loads(message)
            print("WS message received :",message)
            match data["type"]:
                case "register":
                    self.waiting_clients[self.currentWaiting] = {"connection": websocket, "uid": data["uid"]}
                    self.currentWaiting += 1
                    answer = {"type": "register_request", "servId": self.id, "connectionId": self.currentWaiting - 1}
                    await websocket.send(json.dumps(answer))
                case "unregister":
                    print("unregister received")
                    if self.checkWSAuth(websocket,data["clientID"]):
                        client = self.db.getSomething("active_client", data["clientID"])
                        self.db.deleteSomething("active_client",data["clientID"])
                        self.db.deleteSomething("subscription",data["clientID"],selector="client")
                        self.pool.pop(data["clientID"])
                        await self.sendStatusUpdatesAsync(client["userid"])
                    else:
                        self.waiting_clients.pop(data["clientID"])
                case _:
                    print("unknown message received", message)

App(path=PATH, configFile="/server.ini")