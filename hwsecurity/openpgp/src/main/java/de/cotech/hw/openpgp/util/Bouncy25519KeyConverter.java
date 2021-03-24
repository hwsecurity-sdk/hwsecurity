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

package de.cotech.hw.openpgp.util;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import de.cotech.hw.util.Arrays;
import de.cotech.hw.util.HwTimber;
import de.cotech.hw.util.Hwsecurity25519PublicKey;

public class Bouncy25519KeyConverter {

    public static PublicKey hwsecurityToBouncy(PublicKey publicKey) throws IOException {
        if ("X25519".equals(publicKey.getAlgorithm()) && "hwsecurity".equals(publicKey.getFormat())) {
            try {
                SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), publicKey.getEncoded());
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
                KeyFactory keyFactory = KeyFactory.getInstance("X25519", BouncyCastleProvider.PROVIDER_NAME);
                PublicKey bcPublicKey = keyFactory.generatePublic(keySpec);

                HwTimber.d("Raw public key converted to Bouncy Castle BCXDHPublicKey");
                return bcPublicKey;
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                throw new IOException(e);
            }
        } else if ("Ed25519".equals(publicKey.getAlgorithm()) && "hwsecurity".equals(publicKey.getFormat())) {
            try {
                SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), publicKey.getEncoded());
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
                KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
                PublicKey bcPublicKey = keyFactory.generatePublic(keySpec);

                HwTimber.d("Raw public key converted to Bouncy Castle BCEdDSAPublicKey");
                return bcPublicKey;
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                throw new IOException(e);
            }
        } else {
            HwTimber.d("Already in compatible format. Returning PublicKey object.");
            return publicKey;
        }
    }

    public static Hwsecurity25519PublicKey bouncyToHwsecurity(PublicKey publicKey) {
        if (!"Ed25519".equals(publicKey.getAlgorithm())
                && !"X25519".equals(publicKey.getAlgorithm())) {
            throw new IllegalStateException("Unsupported algorithm");
        }
        // remove BC prefix from BCEdDSAPublicKey
        // see https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/edec/KeyFactorySpi.java
        byte[] encodedBcKey = publicKey.getEncoded();
        byte[] withoutPrefix = Arrays.copyOfRange(encodedBcKey, 12, encodedBcKey.length);
        return new Hwsecurity25519PublicKey(withoutPrefix, publicKey.getAlgorithm());
    }
}
