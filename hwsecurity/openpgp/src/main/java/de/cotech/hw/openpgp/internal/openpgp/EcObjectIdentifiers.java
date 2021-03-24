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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;

import de.cotech.hw.util.HwTimber;

// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-9.2
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class EcObjectIdentifiers {

    public static final ASN1ObjectIdentifier NIST_P_256 = SECObjectIdentifiers.secp256r1;
    public static final ASN1ObjectIdentifier NIST_P_384 = SECObjectIdentifiers.secp384r1;
    public static final ASN1ObjectIdentifier NIST_P_521 = SECObjectIdentifiers.secp521r1;
    public static final ASN1ObjectIdentifier BRAINPOOL_P256_R1 = TeleTrusTObjectIdentifiers.brainpoolP256r1;
    public static final ASN1ObjectIdentifier BRAINPOOL_P512_R1 = TeleTrusTObjectIdentifiers.brainpoolP512r1;
    public static final ASN1ObjectIdentifier ED25519 = GNUObjectIdentifiers.Ed25519; // for use with EdDSA
    public static final ASN1ObjectIdentifier X25519 = CryptlibObjectIdentifiers.curvey25519; // for use with ECDH

    public static HashSet<ASN1ObjectIdentifier> sOids = new HashSet<>(Arrays.asList(
            NIST_P_256, NIST_P_384, NIST_P_521, BRAINPOOL_P256_R1, BRAINPOOL_P512_R1, ED25519, X25519
    ));

    public static ASN1ObjectIdentifier parseOid(byte[] oidField) {
        ASN1ObjectIdentifier asn1CurveOid = oidFieldToOidAsn1(oidField);
        if (sOids.contains(asn1CurveOid)) {
            return asn1CurveOid;
        }
        HwTimber.w("Unknown curve OID: %s. Could be YubiKey firmware bug < 5.2.8. Trying again with last byte removed.", asn1CurveOid.getId());

        // https://bugs.chromium.org/p/chromium/issues/detail?id=1120933#c10
        // The OpenPGP applet of a Yubikey with firmware version below 5.2.8 appends
        // a potentially arbitrary byte to the intended byte representation of an ECC
        // curve OID. This case is handled by retrying the decoding with the last
        // byte stripped if the resulting OID does not label a known curve.
        byte[] oidRemoveLastByte = Arrays.copyOf(oidField, oidField.length - 1);
        ASN1ObjectIdentifier asn1CurveOidYubikey = oidFieldToOidAsn1(oidRemoveLastByte);
        if (sOids.contains(asn1CurveOidYubikey)) {
            HwTimber.w("Detected curve OID: %s", asn1CurveOidYubikey.getId());
        } else {
            HwTimber.e("Still Unknown curve OID: %s", asn1CurveOidYubikey.getId());
        }
        return asn1CurveOidYubikey;
    }

    public static byte[] asn1ToOidField(ASN1ObjectIdentifier oidAsn1) {
        byte[] encodedAsn1Oid;
        try {
            encodedAsn1Oid = oidAsn1.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode curve OID!");
        }
        byte[] oidField = new byte[encodedAsn1Oid.length - 2];
        System.arraycopy(encodedAsn1Oid, 2, oidField, 0, encodedAsn1Oid.length - 2);

        return oidField;
    }

    public static ASN1ObjectIdentifier oidFieldToOidAsn1(byte[] oidField) {
        final byte[] boid = new byte[2 + oidField.length];
        boid[0] = (byte) 0x06;
        boid[1] = (byte) oidField.length;
        System.arraycopy(oidField, 0, boid, 2, oidField.length);
        return ASN1ObjectIdentifier.getInstance(boid);
    }

}
