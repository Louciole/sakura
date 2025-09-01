import global from "./global.mjs";
import {onMessage} from "../ws/onMessage.mjs";
import {WEBSOCKETS} from "/config";


export function initWebSockets(){
    global.state.socket = new WebSocket(WEBSOCKETS);

    global.state.socket.onopen = function(event) {
        console.log("Connection opened to Python WebSocket server!");
        const message = {"type" : 'register', "uid": global.user.id};
        global.state.socket.send(JSON.stringify(message));
    };

    global.state.socket.onmessage = onMessage

    global.state.socket.onerror = function(error) {
        console.error("WebSocket error:", error);
    };
}
