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


import de.cotech.hw.fido2.domain.CollectedClientData;
import de.cotech.hw.fido2.internal.utils.WebsafeBase64;
import org.json.JSONException;
import org.json.JSONObject;


public class JsonCollectedClientDataSerializer {
    public String clientClientDataToJson(CollectedClientData clientData) {
        try {
            JSONObject result = new JSONObject();
            result.put("type", clientData.type());
            result.put("origin", clientData.origin());
            result.put("challenge", WebsafeBase64.encodeToString(clientData.challenge()));
            result.put("hashAlgorithm", clientData.hashAlgorithm());
            return result.toString();
        } catch (JSONException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
