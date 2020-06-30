function () {

    console.log("webauthnbridge start execution");

    const webauthnbridge = window.webauthnbridge = {};

    webauthnbridge.reqCounter = 0;

    // Is called from Java
    webauthnbridge.responseHandler = function(message) {
        const response = message;
        const reqId = response['requestId'];
        if (!reqId || !webauthnbridge.callbackMap[reqId]) {
            console.error('Unknown or missing requestId in response.');
            return;
        }
        const cb = webauthnbridge.callbackMap[reqId];
        delete webauthnbridge.callbackMap[reqId];
        cb(response['responseData']);
    };

    const jsonArrayFix = function(k, v) {
        if (v instanceof ArrayBuffer) {
            return new Uint8Array(v);
        }
        return v;
    };

    const decodeWebsafeBase64 = function(websafeBase64) {
        const base64 = websafeBase64.replace(/_/g, '/').replace(/-/g, '+');
        return Uint8Array.from(atob(base64), c=>c.charCodeAt(0))
    };

    navigator.credentials = function() {
    }

    // overrides Browser API: https://www.w3.org/TR/credential-management-1
    navigator.credentials.get = function(opt_options) {
        return new Promise((resolve, reject) => {
            webauthnbridge.current_resolve = resolve;
            webauthnbridge.current_reject = reject;
            const jsonMessage = JSON.stringify(opt_options, jsonArrayFix);
            webauthnbridgejava.get(jsonMessage);
        });
    };

    navigator.credentials.store = function(credential) {
        return new Promise((resolve, reject) => {
            const jsonMessage = JSON.stringify(credential);
            webauthnbridgejava.store(jsonMessage);
        });
    };

    navigator.credentials.create = function(opt_options) {
        return new Promise((resolve, reject) => {
            webauthnbridge.current_resolve = resolve;
            webauthnbridge.current_reject = reject;
            const jsonMessage = JSON.stringify(opt_options, jsonArrayFix);
            webauthnbridgejava.create(jsonMessage);
        });
    };

    navigator.credentials.preventSilentAccess = function() {
        // calls to Java
        webauthnbridgejava.preventSilentAccess();
    };

    window.PublicKeyCredential = function() {
    }

    // Fakes Windows Hello support
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/isUserVerifyingPlatformAuthenticatorAvailable
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = function(opt_options) {
       return Promise.resolve(true);
    };

    // Fakes Windows Hello support
    // https://github.com/w3c/webauthn/issues/1173
    window.PublicKeyCredential.isExternalCTAP2SecurityKeySupported = function(opt_options) {
       return Promise.resolve(true);
    };

    webauthnbridge.handleReject = function(error) {
        webauthnbridge.current_reject(error);
    }

    webauthnbridge.handleResolve = function(obj) {
        console.log(JSON.stringify(obj));

        obj.rawId = decodeWebsafeBase64(obj.id);

        obj.response.clientDataJSON = decodeWebsafeBase64(obj.response.clientDataJsonB64);
        delete obj.response.clientDataJsonB64;

        if (obj.response.attestationObjectB64) {
            obj.response.attestationObject = decodeWebsafeBase64(obj.response.attestationObjectB64);
            delete obj.response.attestationObjectB64;
        }

        if (obj.response.signatureB64) {
            obj.response.signature = decodeWebsafeBase64(obj.response.signatureB64);
            delete obj.response.signatureB64;
        }

        if (obj.response.authenticatorDataB64) {
            obj.response.authenticatorData = decodeWebsafeBase64(obj.response.authenticatorDataB64);
            delete obj.response.authenticatorDataB64;
        }

        if (obj.response.userHandleB64) {
            obj.response.userHandle = decodeWebsafeBase64(obj.response.userHandleB64);
            delete obj.response.userHandleB64;
        } else {
            obj.response.userHandle = null;
        }

        obj.getClientExtensionResults = function () { return {}; };

        console.log(JSON.stringify(obj));
        webauthnbridge.current_resolve(obj);
    }

    console.log("webauthnbridge end execution");
}
