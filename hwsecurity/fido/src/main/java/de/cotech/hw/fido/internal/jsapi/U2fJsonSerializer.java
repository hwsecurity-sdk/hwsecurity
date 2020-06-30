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


import de.cotech.hw.fido.WebsafeBase64;
import de.cotech.hw.fido.internal.jsapi.U2fResponse.ErrorResponseData;
import de.cotech.hw.fido.internal.jsapi.U2fResponse.RegisterResponseData;
import de.cotech.hw.fido.internal.jsapi.U2fResponse.SignResponseData;
import org.json.JSONException;
import org.json.JSONObject;


public class U2fJsonSerializer {
    public static String responseToJson(U2fResponse u2fResponse) {
        try {
            return responseToJsonObject(u2fResponse).toString();
        } catch (JSONException e) {
            throw new IllegalStateException();
        }
    }

    private static JSONObject responseToJsonObject(U2fResponse u2fResponse) throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", u2fResponse.type());
        if (u2fResponse.requestId() != null) {
            jsonObject.put("requestId", u2fResponse.requestId());
        }

        if (u2fResponse.responseData() instanceof RegisterResponseData) {
            jsonObject.put("responseData", registerResponseToJsonObject(
                    (RegisterResponseData) u2fResponse.responseData()));
        } else if (u2fResponse.responseData() instanceof SignResponseData) {
            jsonObject.put("responseData", signResponseToJsonObject(
                    (SignResponseData) u2fResponse.responseData()));
        } else if (u2fResponse.responseData() instanceof ErrorResponseData) {
            jsonObject.put("responseData", errorResponseToJsonObject(
                    (ErrorResponseData) u2fResponse.responseData()));
        } else {
            throw new IllegalStateException("Unimplemented response type!");
        }

        return jsonObject;
    }

    private static JSONObject registerResponseToJsonObject(
            RegisterResponseData responseData) throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("version", responseData.version());
        jsonObject.put("registrationData", WebsafeBase64.encodeToString(responseData.registrationData()));
        jsonObject.put("clientData", WebsafeBase64.encodeToString(responseData.clientData()));
        return jsonObject;
    }

    private static JSONObject signResponseToJsonObject(SignResponseData responseData) throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("keyHandle", WebsafeBase64.encodeToString(responseData.keyHandle()));
        jsonObject.put("signatureData", WebsafeBase64.encodeToString(responseData.signatureData()));
        jsonObject.put("clientData", WebsafeBase64.encodeToString(responseData.clientData()));
        return jsonObject;
    }

    private static JSONObject errorResponseToJsonObject(ErrorResponseData responseData) throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("errorCode", responseData.errorCode().value);
        if (responseData.errorMessage() != null) {
            jsonObject.put("errorMessage", responseData.errorMessage());
        }
        return jsonObject;
    }
}
