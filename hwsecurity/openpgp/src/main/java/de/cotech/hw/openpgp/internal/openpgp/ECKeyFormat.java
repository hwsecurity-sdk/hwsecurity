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


import java.io.IOException;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import com.google.auto.value.AutoValue;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


// 4.3.3.6 Algorithm Attributes
@RestrictTo(Scope.LIBRARY_GROUP)
@AutoValue
public abstract class ECKeyFormat extends KeyFormat {

    @Nullable
    public abstract ASN1ObjectIdentifier curveOid();

    @Nullable // TODO
    public abstract ECAlgorithmFormat ecAlgorithmFormat();

    private static final byte ATTRS_IMPORT_FORMAT_WITH_PUBKEY = (byte) 0xff;

    ECKeyFormat() {
        super(KeyFormatType.ECKeyFormatType);
    }

    public static KeyFormat getInstance(ASN1ObjectIdentifier oid, ECAlgorithmFormat from) {
        return new AutoValue_ECKeyFormat(oid, from);
    }

    public static ECKeyFormat getInstanceECDSAwithOid(ASN1ObjectIdentifier curveOid) {
        return new AutoValue_ECKeyFormat(curveOid, ECAlgorithmFormat.ECDSA_WITH_PUBKEY);
    }

    public static ECKeyFormat getInstanceECDHwithOid(ASN1ObjectIdentifier curveOid) {
        return new AutoValue_ECKeyFormat(curveOid, ECAlgorithmFormat.ECDH_WITH_PUBKEY);
    }

    public static KeyFormat getInstanceFromBytes(byte[] bytes) {
        if (bytes.length < 2) {
            throw new IllegalArgumentException("Bad length for EC attributes");
        }

        int len = bytes.length - 1;
        if (bytes[bytes.length - 1] == ATTRS_IMPORT_FORMAT_WITH_PUBKEY) {
            len -= 1;
        }

        final byte[] boid = new byte[2 + len];
        boid[0] = (byte) 0x06;
        boid[1] = (byte) len;
        System.arraycopy(bytes, 1, boid, 2, len);
        final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(boid);
        return getInstance(oid, ECKeyFormat.ECAlgorithmFormat.from(bytes[0], bytes[bytes.length - 1]));
    }

    public byte[] toBytes(KeyType slot) {
        byte[] oid;
        try {
            oid = curveOid().getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode curve oid!");
        }
        byte[] attrs = new byte[1 + (oid.length - 2) + 1];

        attrs[0] = ecAlgorithmFormat().getAlgorithmId();
        System.arraycopy(oid, 2, attrs, 1, (oid.length - 2));
        attrs[attrs.length - 1] = ATTRS_IMPORT_FORMAT_WITH_PUBKEY;

        return attrs;
    }

    @Override
    public KeyFormatParser getKeyFormatParser() {
        return new ECKeyFormatParser(curveOid());
    }

    public enum ECAlgorithmFormat {
        ECDH((byte) PublicKeyAlgorithmTags.ECDH, true, false),
        ECDH_WITH_PUBKEY((byte) PublicKeyAlgorithmTags.ECDH, true, true),
        ECDSA((byte) PublicKeyAlgorithmTags.ECDSA, false, false),
        ECDSA_WITH_PUBKEY((byte)PublicKeyAlgorithmTags.ECDSA, false, true);

        private final byte mAlgorithmId;
        private final boolean mIsECDH;
        private final boolean mWithPubkey;

        ECAlgorithmFormat(final byte algorithmId, final boolean isECDH, final boolean withPubkey) {
            mAlgorithmId = algorithmId;
            mIsECDH = isECDH;
            mWithPubkey = withPubkey;
        }

        public static ECKeyFormat.ECAlgorithmFormat from(final byte bFirst, final byte bLast) {
            for (ECKeyFormat.ECAlgorithmFormat format : values()) {
                if (format.mAlgorithmId == bFirst &&
                        ((bLast == ATTRS_IMPORT_FORMAT_WITH_PUBKEY) == format.isWithPubkey())) {
                    return format;
                }
            }
            return null;
        }

        public final byte getAlgorithmId() {
            return mAlgorithmId;
        }

        public final boolean isECDH() {
            return mIsECDH;
        }

        public final boolean isWithPubkey() {
            return mWithPubkey;
        }
    }
}
