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

package de.cotech.hw.fido2.internal.json;


import de.cotech.hw.fido2.internal.utils.WebsafeBase64;
import de.cotech.hw.fido2.domain.create.AuthenticatorAttestationResponse;
import de.cotech.hw.fido2.domain.get.AuthenticatorAssertionResponse;
import de.cotech.hw.fido2.domain.AuthenticatorResponse;
import de.cotech.hw.fido2.PublicKeyCredential;
import org.json.JSONException;
import org.json.JSONObject;


public class JsonPublicKeyCredentialSerializer {
    public String publicKeyCredentialToJsonString(PublicKeyCredential publicKeyCredential) {
        return publicKeyCredentialToJson(publicKeyCredential).toString();
    }

    private JSONObject publicKeyCredentialToJson(PublicKeyCredential publicKeyCredential) {
        try {
            JSONObject result = new JSONObject();
            result.put("type", publicKeyCredential.type());
            result.put("id", publicKeyCredential.id());
            result.put("response", authenticatorResponseToJson(publicKeyCredential.response()));
            return result;
        } catch (JSONException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private JSONObject authenticatorResponseToJson(AuthenticatorResponse authenticatorResponse) {
        try {
            JSONObject result = new JSONObject();
            result.put("clientDataJsonB64", WebsafeBase64.encodeToString(authenticatorResponse.clientDataJson()));
            if (authenticatorResponse instanceof AuthenticatorAttestationResponse) {
                AuthenticatorAttestationResponse authenticatorAttestationResponse =
                        (AuthenticatorAttestationResponse) authenticatorResponse;
                String attestationObjectB64 = WebsafeBase64.encodeToString(
                        authenticatorAttestationResponse.attestationObject());
                result.put("attestationObjectB64", attestationObjectB64);
            }
            if (authenticatorResponse instanceof AuthenticatorAssertionResponse) {
                AuthenticatorAssertionResponse authenticatorAttestationResponse =
                        (AuthenticatorAssertionResponse) authenticatorResponse;
                String authenticatorDataB64 = WebsafeBase64.encodeToString(
                        authenticatorAttestationResponse.authenticatorData());
                result.put("authenticatorDataB64", authenticatorDataB64);
                String signatureB64 = WebsafeBase64.encodeToString(
                        authenticatorAttestationResponse.signature());
                result.put("signatureB64", signatureB64);

                byte[] userHandle = authenticatorAttestationResponse.userHandle();
                if (userHandle != null) {
                    String userHandleB64 = WebsafeBase64.encodeToString(userHandle);
                    result.put("userHandleB64", userHandleB64);
                }
            }
            return result;
        } catch (JSONException e) {
            throw new IllegalArgumentException(e);
        }
    }
}