/*
 * Copyright (C) 2018-2021 Confidential Technologies GmbH
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

import com.google.auto.value.AutoValue;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;


// OpenPGP Card Spec: Algorithm Attributes: ECC
@RestrictTo(Scope.LIBRARY_GROUP)
@AutoValue
public abstract class EcKeyFormat extends KeyFormat {

    public abstract int algorithmId();

    public abstract ASN1ObjectIdentifier curveOid();

    public abstract boolean withPubkey();

    private static final byte ATTRS_IMPORT_FORMAT_WITH_PUBKEY = (byte) 0xff;

    public static EcKeyFormat getInstance(int algorithmId, ASN1ObjectIdentifier oid, boolean withPubkey) {
        return new AutoValue_EcKeyFormat(algorithmId, oid, withPubkey);
    }

    public static EcKeyFormat getInstanceForKeyGeneration(KeyType keyType, ASN1ObjectIdentifier oidAsn1) {
        if (keyType == KeyType.ENCRYPT) {
            return getInstance(PublicKeyAlgorithmTags.ECDH, oidAsn1, true);
        } else { // SIGN, AUTH
            if (EcObjectIdentifiers.ED25519.equals(oidAsn1)) {
                return getInstance(PublicKeyAlgorithmTags.EDDSA, oidAsn1, true);
            } else {
                return getInstance(PublicKeyAlgorithmTags.ECDSA, oidAsn1, true);
            }
        }
    }

    public static EcKeyFormat getInstanceFromBytes(byte[] bytes) {
        if (bytes.length < 2) {
            throw new IllegalArgumentException("Bad length for EC attributes");
        }

        int algorithmId = bytes[0];
        int oidLen = bytes.length - 1;

        boolean withPubkey = false;
        if (bytes[bytes.length - 1] == ATTRS_IMPORT_FORMAT_WITH_PUBKEY) {
            withPubkey = true;
            oidLen -= 1;
        }

        final byte[] oidField = new byte[oidLen];
        System.arraycopy(bytes, 1, oidField, 0, oidLen);
        ASN1ObjectIdentifier oid = EcObjectIdentifiers.parseOid(oidField);

        return getInstance(algorithmId, oid, withPubkey);
    }

    public byte[] toBytes(KeyType slot) {
        byte[] oidField = EcObjectIdentifiers.asn1ToOidField(curveOid());

        int len = 1 + oidField.length;
        if (withPubkey()) {
            len += 1;
        }
        byte[] attrs = new byte[len];

        attrs[0] = (byte) algorithmId();
        System.arraycopy(oidField, 0, attrs, 1, oidField.length);
        if (withPubkey()) {
            attrs[len - 1] = ATTRS_IMPORT_FORMAT_WITH_PUBKEY;
        }

        return attrs;
    }

    public boolean isX25519() {
        return EcObjectIdentifiers.X25519.equals(curveOid());
    }

    public final boolean isEdDsa() {
        return algorithmId() == PublicKeyAlgorithmTags.EDDSA;
    }

    @Override
    public KeyFormatParser getKeyFormatParser() {
        return new EcKeyFormatParser(curveOid());
    }

}
