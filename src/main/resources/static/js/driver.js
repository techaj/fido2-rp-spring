/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var preformatMakeCredReq = (makeCredReq) => {
    console.info("Updating credentials ", makeCredReq)
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id = base64url.decode(makeCredReq.user.id);
    return makeCredReq
}

var publicKeyCredentialToJSON = (pubKeyCred) => {
    if (pubKeyCred instanceof Array) {
        let arr = [];
        for (let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));
        return arr
    }

    if (pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
    }
    if (pubKeyCred instanceof Object) {
        let obj = {};

        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }

        return obj
    }

    return pubKeyCred
}

var preformatGetAssertReq = (getAssert) => {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    for (let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }
    return getAssert
}

function init() {
    try {
        PublicKeyCredential;
    } catch (err) {
        displayError("Web Authentication API not found");
    }

    if (document.location.origin.startsWith("http://")) {
        displayError("Loaded outside of a secure context. It shouldn't work.");
    }
    clearSuccess();
    clearError();
    clearLoading();
    hideForms();
    if (isBrowserCompatible()) {
        $("#registerForm").show();
        $("#loginForm").show();
    } else {
        displayError("Incompatible browser.");
    }
    $("#registerForm").submit(processRegisterForm);
    $("#loginForm").submit(processLoginForm);
}

function displayError(message) {
    hideForms();
    clearLoading();
    clearSuccess();
    $("#errMessage").text(message);
    $("#error").show();
}

function clearLoading() {
    $("#loadingText").text("");
    $("#loading").hide();
}

function hideForms() {
    $("#registerForm").hide();
    $("#loginForm").hide();
}

function displayLoading(message) {
    hideForms();
    clearSuccess();
    $("#loadingText").text(message);
    $("#loading").show();
}

function clearError() {
    $("#errMessage").text("");
    $("#error").hide();
}

function goHome() {
    clearLoading();
    clearError();
    window.history.back();
}

function displaySuccess(message) {
    hideForms();
    clearLoading();
    $("#successMessage").text(message);
    $("#success").show();
}

function clearSuccess() {
    $("#successMessage").text();
    $("#success").hide();
}

function processRegisterForm(e) {
    if (e.preventDefault) e.preventDefault();
    hideForms();
    clearSuccess();
    displayLoading("Contacting token... please perform your verification gesture (e.g., touch it, or plug it in)\n\n");

//    let rpid = 'gh-50v0y52.corp.mastercard.org';
    let rpid = document.domain;
    let formBody = {"username": $("#username").val(), "displayName": $("#alias").val()};
    fetch('/attestation/options', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    }).then(
        response => {
            response.json().then(
                data => {
                    if (response.status === 200) {
                        console.log(data);
                        let v = preformatMakeCredReq(data);
                        console.info("Updated Response from FIDO RP server ", v)
                        console.info("RP Domain = ", rpid)
                        v.rp.id = rpid;
                        navigator.credentials.create({publicKey: v})
                            .then(function (aNewCredentialInfo) {
                                var response = publicKeyCredentialToJSON(aNewCredentialInfo);
                                console.info("response = " + response)
                                console.info("response = " + JSON.stringify(response))
                                fetch('/attestation/result', {
                                        method: 'POST',
                                        credentials: 'include',
                                        headers: {
                                            'Content-Type': 'application/json'
                                        },
                                        body: JSON.stringify(response)
                                    }
                                ).then(
                                    response => {
                                        response.json().then(
                                            data => {
                                                if (response.status === 200) {
                                                    displaySuccess("Successful registration! ")
                                                    $('#successMessage').append('<a href="./login.html">Click here to log in</a>');
                                                } else {
                                                    displayError(data)
                                                }
                                            }
                                        )
                                    }
                                )
                            }).catch(function (error) {
                                console.error("respones = " + error)
                            }
                        )
                    }
                    else {
                        displayError(`Server responed with error. The message is: ${response.message}`);
                    }
                }
            )
        }
    )
    return false;
}


function processLoginForm(e) {
    if (e.preventDefault) e.preventDefault();
    hideForms();
    clearSuccess();
    displayLoading("Contacting token... please perform your verification gesture (e.g., touch it, or plug it in)\n\n");

    $("#getOut").text("");

    $("#getOut").text("Contacting token... please perform your verification gesture (e.g., touch it, or plug it in)\n\n");

    let rpid = document.domain;
    let formBody = {"username": $("#loginUsername").val(), "documentDomain": rpid};

    fetch('/assertion/options', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    }).then(
        response => {
            response.json().then(
                data => {
                    if (response.status === 200) {
                        console.info("Updated Response from FIDO RP server ", data)
                        var resp = preformatGetAssertReq(data)
                        console.info("Updated Response from FIDO RP server ", resp)
                        var key = navigator.credentials.get({publicKey: resp})
                        key.then(aAssertion => {
                            console.log(aAssertion)
                            var resp = JSON.stringify(publicKeyCredentialToJSON(aAssertion));
                            console.info("Get Assertion Response " + data);
                            fetch('/assertion/result', {
                                method: 'POST',
                                credentials: 'include',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: resp
                            }).then(
                                response => {
                                    response.json().then(
                                        data => {
                                            if (response.status === 200) {
                                                displaySuccess("Successful match [" + data.status + "]");
                                            } else {
                                                displayError("Failure [" + data.status + "-" + data.errorMessage + "]");
                                            }
                                        }
                                    )
                                }
                            )
                        }).catch(function (aErr) {
                            displayError("Unable to get Assertion Response ", JSON.stringify(aErr));
                        });
                    } else {
                        displayError(`Server responed with error. The message is: ${data.errorMessage}`);
                    }
                }
            )
        }
    )
}


function isBrowserCompatible() {
    return navigator && navigator.credentials && typeof (navigator.credentials.create) === 'function';
}

$(document).ready(function () {
    init();

    $("#getButton").click(function () {

    });
});
