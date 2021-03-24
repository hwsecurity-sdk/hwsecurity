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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import de.cotech.hw.internal.iso7816.Iso7816TLV;
import de.cotech.hw.util.Hex;
import de.cotech.hw.util.HwTimber;
import de.cotech.hw.util.Hwsecurity25519PublicKey;


@RestrictTo(Scope.LIBRARY_GROUP)
public class EcKeyFormatParser implements KeyFormatParser {

    private static final int DO_ECC_PUBKEY_TAG = 0x86;

    private final ASN1ObjectIdentifier curveOid;

    EcKeyFormatParser(ASN1ObjectIdentifier curveOid) {
        this.curveOid = curveOid;
    }

    @Override
    public PublicKey parseKey(byte[] publicKeyBytes) throws IOException {
        Iso7816TLV publicKeyTlv = Iso7816TLV.readSingle(publicKeyBytes, true);
        Iso7816TLV eccEncodedPoints = Iso7816TLV.findRecursive(publicKeyTlv, DO_ECC_PUBKEY_TAG);
        if (eccEncodedPoints == null) {
            throw new IOException("Missing ECC public key data (tag 0x86)");
        }
        byte[] pEnc = eccEncodedPoints.mV;

        if (EcObjectIdentifiers.X25519.equals(curveOid)) {
            Hwsecurity25519PublicKey publicKey = new Hwsecurity25519PublicKey(pEnc, "X25519");

            HwTimber.d("ECC key parsed as X25519. Returned as Hwsecurity25519PublicKey wrapper object");
            return publicKey;
        } else if (EcObjectIdentifiers.ED25519.equals(curveOid)) {
            Hwsecurity25519PublicKey publicKey = new Hwsecurity25519PublicKey(pEnc, "Ed25519");

            HwTimber.d("ECC key parsed as Ed25519. Returned as Hwsecurity25519PublicKey wrapper object");
            return publicKey;
        } else {
            String curveName = ECNamedCurveTable.getName(curveOid);
            X9ECParameters curveParams = ECNamedCurveTable.getByOID(curveOid);
            if (curveParams == null) {
                throw new IOException("Unknown curve OID: " + curveOid.getId());
            }

            try {
                ECNamedCurveSpec params = new ECNamedCurveSpec(curveName, curveParams.getCurve(), curveParams.getG(), curveParams.getN());
                ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pEnc);
                ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
                ECPublicKey publicKey = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(pubKeySpec);

                HwTimber.d("ECC key parsed as %s. Returned as ECPublicKey object.", curveName);
                return publicKey;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IOException(e);
            }
        }
    }

}
