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
import java.util.List;

import de.cotech.hw.util.HwTimber;

public class U2fApiUtils {
    private static final String U2F_VERSION2 = "U2F_V2";

    public static List<byte[]> getKeyHandles(List<U2fRequest.RegisteredKey> registeredKeys) {
        List<byte[]> keyHandles = new ArrayList<>();
        for (U2fRequest.RegisteredKey registeredKey : registeredKeys) {
            byte[] keyHandle = registeredKey.keyHandle();
            keyHandles.add(keyHandle);
        }

        return keyHandles;
    }

    public static String pickChallengeForU2fV2(List<U2fRegisterRequest.RegisterRequest> registerRequests)
            throws IOException {
        for (U2fRegisterRequest.RegisterRequest request : registerRequests) {
            if (U2fApiUtils.U2F_VERSION2.equals(request.version())) {
                HwTimber.d("picking registerRequest: version=%s, challenge=%s", request.version(), request.challenge());
                return request.challenge();
            }
        }

        throw new IOException("unsupported registerRequest version");
    }

}
