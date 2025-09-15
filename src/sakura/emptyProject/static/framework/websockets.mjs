import global from "./global.mjs";
import {onMessage} from "../ws/onMessage.mjs";
import {WEBSOCKETS} from "/config";


export function initWebSockets(){
    global.state.socket = new WebSocket(WEBSOCKETS);

    global.state.socket.onopen = function(event) {
        if (!global.user.id) {
            const cookie = document.cookie.split('; ').find(row => row.startsWith('client' + '='));
            if (cookie) {
                global.user['id'] = cookie.split('=')[1];
            } else {
                console.log("ERROR : INVALID SESSION",document);
            }
        }


        console.log("Connection opened to Python WebSocket server!");
        const message = {"type" : 'register', "uid": global.user.id};
        global.state.socket.send(JSON.stringify(message));
    };

    global.state.socket.onmessage = onMessage

    global.state.socket.onerror = function(error) {
        console.error("WebSocket error:", error);
    };
}
