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

package de.cotech.hw.fido;


import java.util.Collections;
import java.util.List;

import android.os.Parcelable;

import com.google.auto.value.AutoValue;
import androidx.annotation.Nullable;
import org.json.JSONException;
import org.json.JSONObject;


@AutoValue
public abstract class FidoAuthenticateRequest implements Parcelable {
    private static final String REQUEST_TYP_AUTH = "navigator.id.getAssertion";

    public abstract String getAppId();
    public abstract String getFacetId();
    public abstract String getChallenge();
    public abstract List<byte[]> getKeyHandles();
    @Nullable
    public abstract Parcelable getCustomDataParcelable();

    public <T> T getCustomData() {
        // noinspection unchecked
        return (T) getCustomDataParcelable();
    }

    public String getClientData() {
        JSONObject clientData = new JSONObject();
        try {
            clientData.put("typ", REQUEST_TYP_AUTH);
            clientData.put("challenge", getChallenge());
            // (Note: this might be more accurately called 'facet_id', but for compatibility with existing
            // implementations within Chrome we keep the legacy name.)
            clientData.put("origin", getFacetId());
            // TOOD: is cid_pubkey used anywhere?
            clientData.put("cid_pubkey", "unused");
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }

        return clientData.toString();
    }

    public static FidoAuthenticateRequest create(String appId, String facetId, String challenge, byte[] keyHandle) {
        return new AutoValue_FidoAuthenticateRequest(appId, facetId, challenge, Collections.singletonList(keyHandle), null);
    }

    public static FidoAuthenticateRequest create(
            String appId, String facetId, String challenge, byte[] keyHandle, Parcelable customData) {
        return new AutoValue_FidoAuthenticateRequest(
                appId, facetId, challenge, Collections.singletonList(keyHandle), customData);
    }

    public static FidoAuthenticateRequest create(String appId, String facetId, String challenge, List<byte[]> keyHandles) {
        return new AutoValue_FidoAuthenticateRequest(appId, facetId, challenge, keyHandles, null);
    }

    public static FidoAuthenticateRequest create(
            String appId, String facetId, String challenge, List<byte[]> keyHandles, Parcelable customData) {
        return new AutoValue_FidoAuthenticateRequest(appId, facetId, challenge, keyHandles, customData);
    }
}
