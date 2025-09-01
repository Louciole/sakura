import global from "./global.mjs";
import {xhr} from "./templating.mjs";


/**
 * Opens a menu by its DOM id. If the menu element exists, it is displayed. Otherwise, loads the menu template asynchronously.
 * @param {string} id - The DOM id of the menu to open.
 * @param {boolean} [async=true] - Whether to load the template asynchronously if not found.
 */
function openMenu(id, async=true){
    const menu = document.getElementById(id)
    if (menu){
        menu.style.display = "flex"
    }else{
        loadTemplate(id.concat(".html"), undefined, id, async)
    }
}
window.openMenu = openMenu

/**
 * Toggles the display of a menu by its DOM id. If the menu exists, toggles its visibility. Otherwise, loads the menu template.
 * @param {string} id - The DOM id of the menu to toggle.
 * @param {boolean} [async=true] - Whether to load the template asynchronously if not found.
 * @param {HTMLElement} [target=undefined] - Optional target HTML element for template loading.
 */
function toggleMenu(id, async=true,target=undefined){
    const menu = document.getElementById(id)
    if (menu){
        if (menu.style.display === "flex"){
            menu.style.display = "none"
            return
        }
        menu.style.display = "flex"
    }else{
        loadTemplate(id.concat(".html"), target, id, async)
    }
}
window.toggleMenu = toggleMenu

/**
 * Navigates to a new view or section by loading a template and updating selection state.
 *
 * @param {string} id - The id of the element to inject the template into.
 * @param {string} target - The base name of the template to load (without .html).
 * @param {Object} [selected=undefined] - Optional selection context {category | event | id} allowing to add/remove the "selected" class.
 * @param {boolean} [async=true] - Whether to load the template asynchronously.
 * @param {Function} [postInsert=undefined] - Optional callback to run after template insertion.
 *
 */
export function goTo(id, target, selected=undefined, async=true, postInsert=undefined){
    if (postInsert){
        loadTemplate(target.concat(".html"), id, undefined, false)
        postInsert()
    }else{
        loadTemplate(target.concat(".html"), id, undefined, async)
    }
    
    if(selected){
        let targetElt;
        if(global.state[selected.category]){
            global.state[selected.category].classList.remove("selected")
        }else if(selected.event){
            selected.event.currentTarget.parentElement.querySelector('.selected').classList.remove("selected")
        }else if(selected.id){
            targetElt = document.getElementById(selected.id)
            targetElt.parentElement.querySelector('.selected').classList.remove("selected")
        }

        if(selected.event){
            global.state[selected.category] = selected.event.currentTarget
        }else if(selected.id){
            global.state[selected.category] = targetElt
        }
        global.state[selected.category].classList.add("selected")
    }
}
window.goTo = goTo


let openingFM = false;


/**
 * Toggles the visibility of a floating menu (FM) by its DOM id.
 * If another FM is open, it will be hidden and the new one will be shown.
 *
 * @param {string} id - The DOM id of the floating menu to toggle.
 */
function toggleFM(id){
    const FM = document.getElementById(id)
    if(FM !== global.state.activeFM){
        openingFM = true
        if(global.state.activeFM){
            global.state.activeFM.classList.toggle("visible")
        }
        global.state.activeFM = FM
    }
}
window.toggleFM = toggleFM

/**
 * Closes the currently active floating menu (FM) if one is open.
 */
export function closeFM(){
    if(global.state.activeFM){
        global.state.activeFM.classList.toggle("visible")
        global.state.activeFM = undefined
    }
}

/**
 * Toggles the display of a modal window at the mouse event position.
 * If another modal is open, it will be hidden and the new one will be shown at the event's coordinates.
 *
 * @param {string} id - The DOM id of the modal to toggle.
 * @param {Event} event - The event triggering the modal (used for positioning).
 */
function toggleModale(id, event){
    const FM = document.getElementById(id)
    if(FM !== global.state.activeFM){
        openingFM = true
        global.state.modaltarget = event.currentTarget
        if(global.state.activeFM){
            global.state.activeFM.classList.toggle("visible")
        }
        console.log(event.currentTarget,global.state.modaltarget)
        FM.style.top = event.clientY.toString().concat("px")
        FM.style.left = event.clientX.toString().concat("px")
        global.state.activeFM = FM
        if (event.type === "contextmenu"){
            event.preventDefault()
            global.state.activeFM.classList.add("visible")
        }
    }
}
window.toggleModale = toggleModale

/**
 * Toggles the closed/open state of a group element (e.g., collapsible section).
 */
function toggleGroup(){
    event.currentTarget.classList.toggle("closed")
}
window.toggleGroup = toggleGroup

/**
 * Navigates to a specific step in a multi-step menu by translating the menu horizontally.
 *
 * @param {number} step - The step index to navigate to.
 * @param {string} stepsID - The DOM id of the steps container.
 */
function gotoStep(step,stepsID){
    const menu = document.getElementById(stepsID)
    menu.style.transform=`translateX(${-100*step/menu.childElementCount}%)`
}
window.gotoStep = gotoStep

/**
 * Removes the 'selected' class from all elements with class 'selected' inside the given container.
 * Used for resetting selection state in multi-step menus.
 *
 * @param {string} id - The DOM id of the container to reset selection in.
 */
function resetSelected(id){
    const selected = document.getElementById(id).querySelectorAll(".selected")
    for(let el of selected){
        el.classList.remove("selected")
    }
}

/**
 * Closes a menu by hiding it and resetting its state. Can target a specific element or use the event target.
 *
 * @param {string|undefined} cible - CSS selector of the element to close, or undefined to use event target.
 * @param {string} [id='createServerSteps'] - The DOM id of the steps container to reset.
 *
 */
function closeMenu(cible = undefined,id='createServerSteps'){
    if (global.state.disableClose){
        return
    }

    if(!cible){
        if(event.target !== event.currentTarget){
            return
        }
        event.target.style.display = "none";
    }else{
        const cibleEl= document.querySelector(cible)
        cibleEl.style.display = "none";
    }
    gotoStep(0,id)
    resetSelected(id)
}
window.closeMenu = closeMenu

/**
 * Saves the current cursor position in a text input or textarea to global state.
 * Used to paste emojis in a textarea from an emoji-keyboard.
 *
 * @param {Event} event - The input event containing the cursor position.
 */
function saveCursorPosition(event){
    global.state.previousCursor={start:event.srcElement.selectionStart, end:event.srcElement.selectionEnd}
}
window.saveCursorPosition = saveCursorPosition

function isMobileDevice() {
    return /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

export function initNavigation(){
    window.global = global
    global.state.dom = document.querySelector("body")

    const { hostname, port } = window.location;
    global.state.location = { host:hostname, port:port, short:port ? hostname + ":" + port : hostname }

    global.state.isMobile = isMobileDevice()
    if (global.state.isMobile) {
        global.state.dom.classList.add("mobile")

        const onload = function(){
            console.log(this.responseText)
        }
        xhr("/static/mobileUiManifest.mjs", onload)
    }

    if (global.state.socket){
        window.addEventListener('unload', () => {
            if (global.state?.socket.readyState !== WebSocket.CLOSED) {
                const message = {"type" : 'unregister', "clientID":global.state.clientID}
                global.state.socket.send(JSON.stringify(message))
                global.state.socket.close()
            }
        });
    }

}


function print(...args){
    const green ="#68f66e"
    const blue ="#4284f5"
    const yellow ="#fef972"
    const red ="#ee6966"
    const pink ="#fb7bfa"
    const purple ="#6a76fa"

    const colors = [green,blue,green,"white",green,blue,"white",yellow,blue,"white",yellow,"white",yellow,red,pink,purple];
    console.log(`%c${args.join(' ')}`, ...colors.map(c => `color: ${c};`));
    // console.log(colors.map(c => `%c${c}`).join(''), ...colors.map(c => `background: ${c};`));
}


export function printWatermark(name, git){
    print(`                                            %c ${name}\n` +
        "%c⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        %c -----------------------------------\n" +
        "%c⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀       %c  Credits%c: Lou !  \n" +
        `%c⠀⠀⠀⠀⠀⠀⠀⠸⣷⣦⣀⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀        %c Git%c: ${git}\n` +
        "%c⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣦⠀⠠⠾⠿⣿⣷⠀⠀⠀⠀⠀⣠⣤⣄⠀⠀⠀\n" +
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠟⢉⣠⣤⣶⡆⠀⣠⣈⠀⢀⣠⣴⣿⣿⠋⠀⠀⠀⠀      %c Powered by Sakura ! \n" +
        "%c⠀⢀⡀⢀⣀⣀⣠⣤⡄⢀⣀⡘⣿⣿⣿⣷⣼⣿⣿⣷⡄⠹⣿⡿⠁⠀⠀⠀⠀⠀\n" +
        "%c⠀⠀⠻⠿⢿⣿⣿⣿⠁⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣁⠀⠋⠀⠀⠀⠀⠀⠀⠀ \n" +
        "⠀⠀⠀⠀⠀⠀⠈⠻⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢰⣄⣀⠀⠀⠀⠀⠀\n" +
        "%c⠀⠀ ⠀⠀⠀⠀⣠⡀⠀⣴⣿⣿⣿⣿⣿⣿⣿⡿⢿⡿⠀⣾⣿⣿⣿⣿⣶⡄⠀ \n" +
        "⠀⠀⠀⠀⠀⢀⣾⣿⣷⡀⠻⣿⣿⡿⠻⣿⣿⣿⣿⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀\n" +
        "⠀⠀⠀⠀⣠⣾⡿⠟⠉⠉⠀⢀⡉⠁⠀⠛⠛⢉⣠⣴⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀\n" +
        "%c⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⢸⣿⣿⡿⠉⠀⠙⠿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠁⠀⠀⠀⠀⠀⠙⠿⣷⠀⠀⠀⠀⠀⠀⠀\n" +
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀")
}

export function hideLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');

    // Fade out the loading screen
    loadingScreen.classList.add('fade-out');

    // Optional: wait until the transition ends before removing or showing content
    loadingScreen.addEventListener('transitionend', () => {
        loadingScreen.style.display = 'none';
    });
}
