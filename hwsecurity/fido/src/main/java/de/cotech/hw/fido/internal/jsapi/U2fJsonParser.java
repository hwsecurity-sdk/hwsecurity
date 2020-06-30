/*
 * Copyright (C) 2018-2020 Confidential Technologies GmbH
 *
 * You can purchase a commercial license at https://hwsecurity.dev.
 * Buying such a license is mandatory as soon as you develop commercial
 * activities involving this program without disclosing the source code
 * of your own applications.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.cotech.hw.fido.internal.jsapi;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import de.cotech.hw.fido.WebsafeBase64;
import de.cotech.hw.fido.internal.jsapi.U2fRegisterRequest.RegisterRequest;
import de.cotech.hw.fido.internal.jsapi.U2fRequest.RegisteredKey;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


public class U2fJsonParser {
    public static U2fRequest parseU2fRequest(String requestJson) throws IOException {
        try {
            JSONObject jsonObject = new JSONObject(requestJson);
            return parseU2fRequestOrThrow(jsonObject);
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    public static U2fRegisterRequest parseU2fRegisterRequest(String requestJson) throws IOException {
        U2fRequest u2fRequest = parseU2fRequest(requestJson);
        if (u2fRequest instanceof U2fRegisterRequest) {
            return (U2fRegisterRequest) u2fRequest;
        } else {
            throw new IOException("Expected U2fRegisterRequest, found '" + u2fRequest.type() + "'");
        }
    }

    public static U2fAuthenticateRequest parseU2fAuthenticateRequest(String requestJson) throws IOException {
        U2fRequest u2fRequest = parseU2fRequest(requestJson);
        if (u2fRequest instanceof U2fAuthenticateRequest) {
            return (U2fAuthenticateRequest) u2fRequest;
        } else {
            throw new IOException("Expected U2fAuthenticateRequest, found '" + u2fRequest.type() + "'");
        }
    }

    private static U2fRequest parseU2fRequestOrThrow(JSONObject jsonObject) throws JSONException {
        String type = jsonObject.getString("type");
        Long requestId = jsonObject.has("requestId") ?
                jsonObject.getLong("requestId") : null;
        String appId = jsonObject.has("appId") ?
                jsonObject.getString("appId") : null;
        Long timeoutSeconds = jsonObject.has("timeoutSeconds") ?
                jsonObject.getLong("timeoutSeconds") : null;

        switch (type) {
            case U2fRequest.REGISTER_REQUEST_TYPE: {
                return parseU2fRegisterRequestOrThrow(jsonObject, type, appId, requestId, timeoutSeconds);
            }

            case U2fRequest.AUTHENTICATE_REQUEST_TYPE: {
                return parseU2fAuthenticateRequestOrThrow(jsonObject, type, appId, requestId, timeoutSeconds);
            }

            default: {
                return new AutoValue_U2fRequest_UnknownU2fRequest(type, requestId, appId, timeoutSeconds);
            }
        }
    }

    private static U2fAuthenticateRequest parseU2fAuthenticateRequestOrThrow(JSONObject jsonObject,
            String type, String appId, Long requestId, Long timeoutSeconds) throws JSONException {
        String challenge = jsonObject.getString("challenge");
        JSONArray registeredKeysArray = jsonObject.getJSONArray("registeredKeys");
        List<RegisteredKey> registeredKeys = parseRegisteredKeys(registeredKeysArray);

        return new AutoValue_U2fAuthenticateRequest(type, requestId, appId, timeoutSeconds, challenge, registeredKeys);
    }

    private static List<RegisteredKey> parseRegisteredKeys(JSONArray jsonArray) throws JSONException {
        ArrayList<RegisteredKey> result = new ArrayList<>(jsonArray.length());
        for (int i = 0; i < jsonArray.length(); i++) {
            RegisteredKey registeredKey = parseRegisteredKey(jsonArray.getJSONObject(i));
            result.add(registeredKey);
        }
        return Collections.unmodifiableList(result);
    }

    private static RegisteredKey parseRegisteredKey(JSONObject jsonObject) throws JSONException {
        try {
            String keyHandleB64 = jsonObject.getString("keyHandle");
            byte[] keyHandle = WebsafeBase64.decode(keyHandleB64);
            return new AutoValue_U2fRequest_RegisteredKey(keyHandle);
        } catch (IllegalArgumentException e) {
            throw new JSONException("Failed parsing websafe b64 keyHandle value!");
        }
    }

    private static U2fRegisterRequest parseU2fRegisterRequestOrThrow(JSONObject jsonObject,
            String type, String appId, Long requestId, Long timeoutSeconds) throws JSONException {
        JSONArray registerRequestsArray = jsonObject.getJSONArray("registerRequests");
        List<RegisterRequest> registerRequests = parseRegisterRequests(registerRequestsArray);
        JSONArray registeredKeysArray = jsonObject.getJSONArray("registeredKeys");
        List<RegisteredKey> registeredKeys = parseRegisteredKeys(registeredKeysArray);

        return new AutoValue_U2fRegisterRequest(type, requestId, appId, timeoutSeconds, registerRequests, registeredKeys);
    }

    private static List<RegisterRequest> parseRegisterRequests(JSONArray jsonArray) throws JSONException {
        ArrayList<RegisterRequest> result = new ArrayList<>(jsonArray.length());
        for (int i = 0; i < jsonArray.length(); i++) {
            RegisterRequest registerRequest = parseRegisterRequest(jsonArray.getJSONObject(i));
            result.add(registerRequest);
        }
        return Collections.unmodifiableList(result);
    }

    private static RegisterRequest parseRegisterRequest(JSONObject jsonObject) throws JSONException {
        String version = jsonObject.getString("version");
        String challenge = jsonObject.getString("challenge");
        return new AutoValue_U2fRegisterRequest_RegisterRequest(version, challenge);
    }
}
