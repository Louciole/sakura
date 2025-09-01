function logout() {
    const url = "/logout";
    fetch(url, {
        method: 'POST',
        redirect: 'manual'
    })
        .then(response => {
            const location = response.headers.get('location');
            if (response.status === 302 && location) {
                window.location.href = location;
            } else {
                // fallback: reload page or handle error
                window.location.reload();
            }
        })
        .catch(() => {
            console.log("request failed");
        });
}
window.logout = logout



export function updateElement(selector,value=undefined){
    const subscriptions = document.querySelectorAll(`[class^="${selector.replaceAll('.','-').replaceAll('[','🪟').replaceAll(']','🥹')}"]`)
    for (let sub of subscriptions){
        if(sub.dataset.repaint){
            const fn = eval(sub.dataset.repaint)
            fn()
        }else if(sub.dataset.target === "class"){

            const content = eval(sub.dataset.content)
            if(sub.dataset.element){
                sub.className = sub.dataset.defaultClass.concat(' ',content(eval(sub.dataset.element)))
            }else{
                sub.className = sub.dataset.defaultClass.concat(' ',content())
            }
        }else if(sub.dataset.target === "style"){
            const content = eval(sub.dataset.content)
            if(sub.dataset.element){
                sub.style = content(eval(sub.dataset.element))
            }else{
                sub.style = content()
            }
        }else{

            const content = eval(sub.dataset.content)
            if(sub.dataset.element){
                sub.innerHTML = content(eval(sub.dataset.element))
            }else{
                sub.innerHTML = content()
            }
        }
    }
}

export function setElement(element, value){
    // console.log(element,'has been updated to:', value);
    eval(`${element} = value`);
    updateElement(element,value)
}

export function pushElement(element, value){
    // console.log(element,'has been added:', value);
    eval(`${element}.push(value)`);
    updateElement(element,value)
}

export function addElement(element, value){
    // console.log(element,'has been added:', value);
    eval(`${element}[value.id] = value`);
    updateElement(element,value)
}

// this deletes an element from a list BY ID
export function deleteElement(element, id){
    // console.log(element,'has been removed:', element[id]);
    eval(`${element}.splice(id,1)`);
    updateElement(element)
}

// this deletes an element from a list BY VALUE
export function deleteVal(element, val){
    // console.log(element,'has been removed:', element[id]);
    eval(`${element} = ${element}.filter(item => item !== val)`);
    updateElement(element)
}

function checkEnter(event, effect){
    if (event.key === "Enter"){
        effect()
    }
}
window.checkEnter = checkEnter

function getTimeStr(timestamp, options = { locale: "fr-FR" }) {
    const date = new Date(timestamp);

    const defaultOptions = {
        year: "numeric",
        month: "numeric",
        day: "numeric",
        hour: "numeric",
        minute: "numeric",
        hour12: false,
    };

    const mergedOptions = { ...defaultOptions, ...options };
    // console.log("TIMESTR",date.toLocaleDateString(undefined, mergedOptions))
    return date.toLocaleDateString(undefined, mergedOptions);
}
window.getTimeStr = getTimeStr


function goodbye(){
    if (confirm('Voulez-vous vraiment vous désinscrire et supprimer votre compte de tous les services Carbonlab ? (toutes vos informations seront effacées)')) {
        const url = "/goodbye";
        let request = new XMLHttpRequest();
        request.open('POST', url, true);
        request.onload = function() { // request successful
            console.log("account deleted")

            if (request.response === 302){
                window.location.href = request.response.headers.get('location');
            }
        };

        request.onerror = function() {
            console.log("request failed")
        };

        request.send();
    } else {
        console.log("ouf 😖")
    }
}
window.goodbye = goodbye

export function difference(arrKeys, dict) {
    const result = [];
    const dictKeys = new Set(Object.keys(dict)); // Convert dict keys to a set for efficient lookup

    for (const key of arrKeys) {
        if (!dictKeys.has(key.toString())) {
            result.push(key);
        }
    }
    return Array.from(result);
}
