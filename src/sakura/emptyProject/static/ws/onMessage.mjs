import global from "../framework/global.mjs";
import {xhr} from "../framework/templating.mjs";

export function onMessage(event) {
    console.log("Received message from Python server:", event.data);
    const message = JSON.parse(event.data)
    switch (message.type){
        case "register_request":
            //TODO handle multiserver xhr with the received servID

            const effect = function (){
                global.state.clientID = JSON.parse(this.responseText)
                postWS()
            }

            xhr("authWS?connectionId=".concat(message.connectionId),effect)
            break
        default:
            break;
    }
}