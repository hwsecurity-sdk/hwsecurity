// This overrides the U2F Javascript API of the WebView Browser engine
// Only supports high level API of U2F version 1.1
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-javascript-api-v1.2-ps-20170411.html
function () {

    console.log("fidobridge start execution");

    var u2f = window.u2f = {};

    var fidobridge = window.fidobridge = {};

    fidobridge.reqCounter = 0;

    fidobridge.callbackMap = {};

    // Is called from Java
    fidobridge.responseHandler = function(message) {
        var response = message;
        var reqId = response['requestId'];
        if (!reqId || !fidobridge.callbackMap[reqId]) {
            console.error('Unknown or missing requestId in response.');
            return;
        }
        var cb = fidobridge.callbackMap[reqId];
        delete fidobridge.callbackMap[reqId];
        cb(response['responseData']);
    };

    fidobridge.formatRegisterRequest = function(appId, registerRequests, registeredKeys, timeoutSeconds, reqId) {
        // U2F JS 1.1 API
        return {
            type: 'u2f_register_request',
            appId: appId,
            registerRequests: registerRequests,
            registeredKeys: registeredKeys,
            timeoutSeconds: timeoutSeconds,
            requestId: reqId
        };
    };

    fidobridge.formatSignRequest = function(appId, challenge, registeredKeys, timeoutSeconds, reqId) {
        // U2F JS 1.1 API
        return {
            type: 'u2f_sign_request',
            appId: appId,
            challenge: challenge,
            registeredKeys: registeredKeys,
            timeoutSeconds: timeoutSeconds,
            requestId: reqId
        };
    };

    // overrides Browser Javascript API
    u2f.register = function(appId, registerRequests, registeredKeys, callback, opt_timeoutSeconds) {
        var reqId = ++fidobridge.reqCounter;
        fidobridge.callbackMap[reqId] = callback;

        var message = fidobridge.formatRegisterRequest(appId, registerRequests, registeredKeys, opt_timeoutSeconds, reqId);
        var jsonMessage = JSON.stringify(message);
        // calls to Java
        fidobridgejava.register(jsonMessage);
    };

    // overrides Browser Javascript API
    u2f.sign = function(appId, challenge, registeredKeys, callback, opt_timeoutSeconds) {
        var reqId = ++fidobridge.reqCounter;
        fidobridge.callbackMap[reqId] = callback;

        var message = fidobridge.formatSignRequest(appId, challenge, registeredKeys, opt_timeoutSeconds, reqId);
        var jsonMessage = JSON.stringify(message);
        // calls to Java
        fidobridgejava.sign(jsonMessage);
    };

    console.log("fidobridge end execution");

}
