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

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


// 4.3.3.6 Algorithm Attributes
@RestrictTo(Scope.LIBRARY_GROUP)
public class ECKeyFormat extends KeyFormat {

    private final ECAlgorithmFormat mECAlgorithmFormat;
    private final ASN1ObjectIdentifier mECCurveOID;

    public static ECKeyFormat getInstanceECDHwithOid(ASN1ObjectIdentifier curveOid) {
        return new ECKeyFormat(curveOid, ECAlgorithmFormat.ECDH_WITH_PUBKEY);
    }

    public static ECKeyFormat getInstanceECDSAwithOid(ASN1ObjectIdentifier curveOid) {
        return new ECKeyFormat(curveOid, ECAlgorithmFormat.ECDSA_WITH_PUBKEY);
    }

    ECKeyFormat(final ASN1ObjectIdentifier ecCurveOid,
            final ECAlgorithmFormat ecAlgorithmFormat) {
        super(KeyFormatType.ECKeyFormatType);
        mECAlgorithmFormat = ecAlgorithmFormat;
        mECCurveOID = ecCurveOid;
    }

    public ECKeyFormat.ECAlgorithmFormat getAlgorithmFormat() {
        return mECAlgorithmFormat;
    }

    public ASN1ObjectIdentifier getCurveOID() {
        return mECCurveOID;
    }

    public byte[] toBytes(KeyType slot) {
        byte[] oid;
        try {
            oid = mECCurveOID.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode curve oid!");
        }
        byte[] attrs = new byte[1 + (oid.length - 2) + 1];
        attrs[0] = mECAlgorithmFormat.getValue();

        System.arraycopy(oid, 2, attrs, 1, (oid.length - 2));
        attrs[attrs.length - 1] = (byte) 0xff;
        return attrs;
    }

    @Override
    public KeyFormatParser getKeyFormatParser() {
        return new ECKeyFormatParser(mECCurveOID);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ECKeyFormat that = (ECKeyFormat) o;
        return mECAlgorithmFormat.equals(that.mECAlgorithmFormat) &&
                mECCurveOID.equals(that.mECCurveOID);
    }

    @Override
    public int hashCode() {
        int result = mECAlgorithmFormat.hashCode();
        result = 31 * result + mECCurveOID.hashCode();
        return result;
    }

    public enum ECAlgorithmFormat {
        ECDH((byte) 18, true, false),
        ECDH_WITH_PUBKEY((byte) 18, true, true),
        ECDSA((byte) 19, false, false),
        ECDSA_WITH_PUBKEY((byte) 19, false, true);

        private final byte mValue;
        private final boolean mIsECDH;
        private final boolean mWithPubkey;

        ECAlgorithmFormat(final byte value, final boolean isECDH, final boolean withPubkey) {
            mValue = value;
            mIsECDH = isECDH;
            mWithPubkey = withPubkey;
        }

        public static ECKeyFormat.ECAlgorithmFormat from(final byte bFirst, final byte bLast) {
            for (ECKeyFormat.ECAlgorithmFormat format : values()) {
                if (format.mValue == bFirst && ((bLast == (byte) 0xff) == format.isWithPubkey())) {
                    return format;
                }
            }
            return null;
        }

        public final byte getValue() {
            return mValue;
        }

        public final boolean isECDH() {
            return mIsECDH;
        }

        public final boolean isWithPubkey() {
            return mWithPubkey;
        }
    }
}
