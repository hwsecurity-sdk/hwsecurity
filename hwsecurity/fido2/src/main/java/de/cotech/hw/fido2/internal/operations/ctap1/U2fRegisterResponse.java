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

package de.cotech.hw.fido2.internal.operations.ctap1;


import java.io.IOException;
import java.nio.ByteBuffer;

import com.google.auto.value.AutoValue;
import de.cotech.hw.fido2.internal.utils.DerUtils;


@AutoValue
public abstract class U2fRegisterResponse {
    abstract byte[] publicKey();
    abstract byte[] keyHandle();
    abstract byte[] attestationCertificate();
    abstract byte[] signature();

    public static U2fRegisterResponse fromBytes(byte[] data) throws IOException  {
        ByteBuffer buf = ByteBuffer.wrap(data);

        if (buf.get() != 0x05) {
            throw new IOException("Invalid U2F response, first byte must be 0x05!");
        }
        byte[] publicKey = new byte[65];
        buf.get(publicKey);

        int keyHandleLength = buf.get();
        byte[] keyHandle = new byte[keyHandleLength];
        buf.get(keyHandle);

        int attestationSignatureLength = DerUtils.findDerEncodedLength(buf.asReadOnlyBuffer());
        byte[] attestationSignature = new byte[attestationSignatureLength];
        buf.get(attestationSignature);

        int signatureLength = buf.remaining();
        if (signatureLength < 70 || signatureLength > 73) {
            throw new IOException("Signature length must be 71-73 bytes!");
        }
        byte[] signature = new byte[signatureLength];
        buf.get(signature);

        return new AutoValue_U2fRegisterResponse(publicKey, keyHandle, attestationSignature, signature);
    }
}
