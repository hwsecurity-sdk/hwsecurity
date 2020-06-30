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

package de.cotech.hw.fido2.domain;


import android.os.Parcelable;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers.CoseAlg;


@AutoValue
public abstract class PublicKeyCredentialParameters implements Parcelable {
    abstract Map<String, CoseAlg> rawParameters();

    // Pretty ugly, but we can only parcel String keys in a Map type.
    public Map<PublicKeyCredentialType, CoseAlg> parameters() {
        HashMap<PublicKeyCredentialType, CoseAlg> result = new HashMap<>();
        for (Map.Entry<String, CoseAlg> entry : rawParameters().entrySet()) {
            result.put(PublicKeyCredentialType.fromString(entry.getKey()), entry.getValue());
        }
        return Collections.unmodifiableMap(result);
    }

    public static PublicKeyCredentialParameters createSingle(PublicKeyCredentialType type, CoseAlg algorithm) {
        Map<String, CoseAlg> parameters = Collections.singletonMap(type.type, algorithm);
        return new AutoValue_PublicKeyCredentialParameters(parameters);
    }

    public static PublicKeyCredentialParameters createDefaultEs256() {
        return createSingle(PublicKeyCredentialType.PUBLIC_KEY, CoseAlg.ES256);
    }

    public static List<PublicKeyCredentialParameters> createDefaultEs256List() {
        return Collections.singletonList(createDefaultEs256());
    }
}
