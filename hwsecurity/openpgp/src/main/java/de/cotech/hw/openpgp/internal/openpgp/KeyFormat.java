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

package de.cotech.hw.openpgp.internal.openpgp;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

@RestrictTo(Scope.LIBRARY_GROUP)
public abstract class KeyFormat {

    public enum KeyFormatType {
        RSAKeyFormatType,
        ECKeyFormatType,
        EdDSAKeyFormatType
    }

    private final KeyFormatType mKeyFormatType;

    KeyFormat(final KeyFormatType keyFormatType) {
        mKeyFormatType = keyFormatType;
    }

    public final KeyFormatType keyFormatType() {
        return mKeyFormatType;
    }

    public static KeyFormat fromBytes(byte[] bytes) {
        switch (bytes[0]) {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                if (bytes.length < 6) {
                    throw new IllegalArgumentException("Bad length for RSA attributes");
                }
                return new RSAKeyFormat(bytes[1] << 8 | bytes[2],
                                        bytes[3] << 8 | bytes[4],
                                        RSAKeyFormat.RSAAlgorithmFormat.from(bytes[5]));

            case PublicKeyAlgorithmTags.ECDH:
            case PublicKeyAlgorithmTags.ECDSA:
                if (bytes.length < 2) {
                    throw new IllegalArgumentException("Bad length for EC attributes");
                }
                int len = bytes.length - 1;
                if (bytes[bytes.length - 1] == (byte)0xff) {
                    len -= 1;
                }
                final byte[] boid = new byte[2 + len];
                boid[0] = (byte)0x06;
                boid[1] = (byte)len;
                System.arraycopy(bytes, 1, boid, 2, len);
                final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(boid);
                return new ECKeyFormat(oid, ECKeyFormat.ECAlgorithmFormat.from(bytes[0], bytes[bytes.length - 1]));
            case PublicKeyAlgorithmTags.EDDSA:
                return new EdDSAKeyFormat();

            default:
                throw new IllegalArgumentException("Unsupported Algorithm id " + bytes[0]);
        }
    }

    public abstract byte[] toBytes(KeyType slot);

    public abstract KeyFormatParser getKeyFormatParser();
}
