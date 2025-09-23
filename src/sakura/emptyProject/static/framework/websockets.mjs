import global from "./global.mjs";
import {onMessage} from "../ws/onMessage.mjs";
import {WEBSOCKETS} from "/config";


export function initWebSockets(){
    global.state.websocket = new WebSocket(WEBSOCKETS);

    global.state.websocket.onopen = function(event) {
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
        global.state.websocket.send(JSON.stringify(message));
    };

    global.state.websocket.onmessage = onMessage;

    global.state.websocket.onclose = function(event) {
        console.log(`[WS] Connexion closed - Code: ${event.code}, Reason: ${event.reason}`);

        if (event.code !== 1000 && event.code !== 1001) {
            console.log("[WS] Trying to reconnect in 3 secondes...");
            setTimeout(() => {
                initWebSockets();
            }, 3000);
        }
    };

    global.state.websocket.onerror = function(error) {
        console.error("WebSocket error:", error);
    };
}
