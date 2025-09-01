function loginSubmit(event) {
    let url = "/login";
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);

    if (urlParams.has('parrain')){
        const parrain = urlParams.get('parrain')
        url+="?parrain="+parrain
    }

    const errorBox = document.querySelector("#messageframe");
    let request = new XMLHttpRequest();
    request.open('POST', url, true);
    request.onload = function() { // request successful
        console.log(request.responseText)
        if (request.responseText === "ok"){
            if (urlParams.has('ref')){
                const ref = urlParams.get('ref')
                window.location.href = "/" + ref;
            }else{
                window.location.href = "/channels";
            }
        }else if(request.responseText === "verif"){
            if (urlParams.has('ref')){
                const ref = urlParams.get('ref')
                window.location.href = "/verif?ref="+ref
            }else{
                window.location.href = "/verif";
            }
        }else{
            errorBox.innerHTML=request.responseText
        }
    };

    request.onerror = function() {
        console.log("request failed")
    };

    request.send(new FormData(event.target));
    event.preventDefault();
}

function signupSubmit(event){
    const url = "/signup";
    const errorBox = document.querySelector("#messageframe");
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);

    let request = new XMLHttpRequest();
    request.open('POST', url, true);
    request.onload = function() { // request successful
        if (request.responseText === "ok"){
            if (urlParams.has('ref')){
                const ref = urlParams.get('ref')
                window.location.href = "/" + ref;
            }else{
                window.location.href = "/channels";
            }
        }else{
            errorBox.innerHTML=request.responseText
        }
    };

    request.onerror = function() {
        console.log("request failed")
    };

    console.log(new FormData(event.target))
    request.send(new FormData(event.target));
    event.preventDefault();
}

function resetSubmit(event){
    const url = "/changePasswordVerif";
    const errorBox = document.querySelector("#messageframe");

    let request = new XMLHttpRequest();
    request.open('POST', url, true);
    request.onload = function() { // request successful
        if (request.responseText === "ok"){
            window.location.href = "/auth";
        }else{
            errorBox.innerHTML=request.responseText
        }
    };

    request.onerror = function() {
        console.log("request failed")
    };

    console.log(new FormData(event.target))
    request.send(new FormData(event.target));
    event.preventDefault();
}

function attachFormSubmitEvent(formId,fn){
    document.getElementById(formId).addEventListener("submit", fn);
}

function resendValidation(){
    const resendBtn = document.querySelector("#resend");
    setTimeout(() => {activateBtn(resendBtn)}, 10000)
    resendBtn.style.color="lightgray"
    resendBtn.onclick="none"

    const url = "/resendVerif";
    const errorBox = document.querySelector("#messageframe");

    let request = new XMLHttpRequest();
    request.open('POST', url, true);
    request.onload = function() {
    };

    request.onerror = function() {
        console.log("request failed")
    };
    request.send();
}

function activateBtn(btn){
    btn.style.color="grey"
    btn.onclick=resendValidation
}

function initReset(){
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);

    if (urlParams.has('email')){
        const mailBox =  document.getElementById("mail")
        mailBox.value =  urlParams.get('email')
        attachFormSubmitEvent('resetForm',resetSubmit)
    }
}

function askReset(){
    const errorBox = document.querySelector("#messageframe");
    const mail = document.getElementById("email").value
    if (mail === ""){
        errorBox.innerHTML="Please enter your email to reset your password"
        return
    }
    const url = "/passwordReset?email="+mail;

    let request = new XMLHttpRequest();
    request.open('POST', url, true);
    request.onload = function() {
        if (request.responseText === "ok"){
            window.location.href = "/reset?email="+mail;
        }else{
            errorBox.innerHTML=request.responseText
        }
    };

    request.onerror = function() {
        console.log("request failed")
    };
    request.send();
}
