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


import org.junit.Test;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import de.cotech.hw.util.Hex;
import de.cotech.hw.util.Hwsecurity25519PublicKey;

import static org.junit.Assert.assertArrayEquals;

public class Rfc4880FingerprintCalculatorTest {

    private final static byte[] RSA_PUBLIC = Hex.decodeHexOrFail(
            "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b0536771ab357106e33d68599d" +
                    "73f004793b9c0efd693a219136869da721a84d41f813734ee4b7e34bd52757e36b289636f6b1b77096867e7bbd" +
                    "5100b0e9c8c5e4842bae1915694f753be3f8d5f7bf97c3189faa6e5febecd8c5dc06e73f442046b05d831d27e3" +
                    "3bab874ec5cabc8fa0ae5b5a700b493a0a5498d0efc46283c6f09a02fa4cd23a5cdd120d16f8da94b1e24f1cc4" +
                    "3c39c412100687a00dd79fec1454faf5834d0caa9d74bdec08fe746e6f63127008822de32672fde3b6992e179d" +
                    "860b050b12a58293597d4330b6e5eb80383f819c39dd11cc9565eda9bf74c3d635c38850b50e9d18d70281fd59" +
                    "4a4dc6c99dced5a57e9d5a214680b75d36590203010001");

    private final static byte[] RSA_FINGERPRINT = Hex.decodeHexOrFail("61af1d55181bd81e7170a27b57082c2e6a682373");

    private final static byte[] ECC_P256_PUBLIC = Hex.decodeHexOrFail(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004aa0d448dd43f1cae67af7a497cff4aab13ac7" +
                    "9dc32c31881f92911ed8a60c1cb349e9ebe4758910a6f7244c7a25bcc7cc726e168506ceaf69ea26a7c6468a46e"
    );

    private final static byte[] ECDSA_FINGERPRINT = Hex.decodeHexOrFail("b9c2c4e3c51ac1e72242192fdd7c22ea2ae42bf8");

    private final static byte[] ECDH_FINGERPRINT = Hex.decodeHexOrFail("9e382b08d0e6b108d3bebdf8bea2457a7fe6acd8");

    private final static byte[] ED_25519_PUBLIC = Hex.decodeHexOrFail(
            "b7a3c12dc0c8c748ab07525b701122b88bd78f600c76342d27f25e5f92444cde"
    );

    private final static byte[] ED_25519_FINGERPRINT = Hex.decodeHexOrFail("3d63e471725725a831f8768b4f6f6325deb07294");

    private final static byte[] X_25519_FINGERPRINT = Hex.decodeHexOrFail("78c2f872581742e1ae5db925cc5a3a513510e1f1");

    private final static Date FIXED_TIMESTAMP = new Date(946731661000L);

    @Test
    public void rsaFingerprint() throws Exception {
        RSAPublicKey rsaPublicKey = JcaTestUtils.parseRsaPublicKey(RSA_PUBLIC);
        byte[] fingerprint = Rfc4880FingerprintCalculator.calculateRsaFingerprint(rsaPublicKey, FIXED_TIMESTAMP);
        assertArrayEquals(fingerprint, RSA_FINGERPRINT);
    }

    @Test
    public void ecdsaFingerprint() throws Exception {
        ECPublicKey ecPublicKey = JcaTestUtils.parseEcPublicKey(ECC_P256_PUBLIC);
        EcKeyFormat ecKeyFormat = EcKeyFormat.getInstance(PublicKeyAlgorithmTags.ECDSA, EcObjectIdentifiers.NIST_P_256, true);
        byte[] fingerprint = Rfc4880FingerprintCalculator.calculateEccFingerprint(ecPublicKey, ecKeyFormat, FIXED_TIMESTAMP);
        assertArrayEquals(fingerprint, ECDSA_FINGERPRINT);
    }

    @Test
    public void ecdhFingerprint() throws Exception {
        ECPublicKey ecPublicKey = JcaTestUtils.parseEcPublicKey(ECC_P256_PUBLIC);
        EcKeyFormat ecKeyFormat = EcKeyFormat.getInstance(PublicKeyAlgorithmTags.ECDH, EcObjectIdentifiers.NIST_P_256, true);
        byte[] fingerprint = Rfc4880FingerprintCalculator.calculateEccFingerprint(ecPublicKey, ecKeyFormat, FIXED_TIMESTAMP);
        assertArrayEquals(fingerprint, ECDH_FINGERPRINT);
    }

    @Test
    public void ed25519Fingerprint() {
        Hwsecurity25519PublicKey publicKey = new Hwsecurity25519PublicKey(ED_25519_PUBLIC, "Ed25519");
        EcKeyFormat ecKeyFormat = EcKeyFormat.getInstance(PublicKeyAlgorithmTags.EDDSA, EcObjectIdentifiers.ED25519, true);
        byte[] fingerprint = Rfc4880FingerprintCalculator.calculateEccFingerprint(publicKey, ecKeyFormat, FIXED_TIMESTAMP);
        assertArrayEquals(fingerprint, ED_25519_FINGERPRINT);
    }

    @Test
    public void x25519Fingerprint() {
        Hwsecurity25519PublicKey publicKey = new Hwsecurity25519PublicKey(ED_25519_PUBLIC, "X25519");
        EcKeyFormat ecKeyFormat = EcKeyFormat.getInstance(PublicKeyAlgorithmTags.ECDH, EcObjectIdentifiers.X25519, true);
        byte[] fingerprint = Rfc4880FingerprintCalculator.calculateEccFingerprint(publicKey, ecKeyFormat, FIXED_TIMESTAMP);
        assertArrayEquals(fingerprint, X_25519_FINGERPRINT);
    }
}