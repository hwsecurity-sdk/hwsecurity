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

package de.cotech.hw.fido2.internal.ctap2.commands.getInfo;


import java.util.Collections;
import java.util.List;

import androidx.annotation.Nullable;
import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.ctap2.Ctap2Response;


@AutoValue
public abstract class AuthenticatorGetInfoResponse extends Ctap2Response {
    private static final int DEFAULT_MAX_MSG_SIZE = 1024;

    public abstract List<String> versions();
    public abstract List<String> extensions();
    @SuppressWarnings("mutable")
    public abstract byte[] aaguid();
    public abstract AuthenticatorOptions options();
    public abstract int maxMsgSize();
    @Nullable
    public abstract List<Integer> pinProtocols();

    public static AuthenticatorGetInfoResponse create(List<String> versions, List<String> extensions, byte[] aaguid,
            AuthenticatorOptions options, Integer maxMsgSize, List<Integer> pinProtocols) {
        if (extensions == null) {
            extensions = Collections.emptyList();
        }
        if (maxMsgSize == null) {
            maxMsgSize = DEFAULT_MAX_MSG_SIZE;
        }
        return new AutoValue_AuthenticatorGetInfoResponse(versions, extensions, aaguid, options, maxMsgSize, pinProtocols);
    }
}
