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

package de.cotech.hw.ssh;


import de.cotech.hw.util.Hex;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;


public class SshUtilTest {
    private final static byte[] RAW_ECDSA_SIGNATURE = Hex.decodeHexOrFail(
            "3046" +
                    "0221" +
                    "00949fa9151d71495d9c020635dcedac6a" +
                    "8665d079b4f721b05a9408771e455fe2" +
                    "0221" +
                    "00df9c7a5ae59e5d2e42d3767e1525c825" +
                    "7cff82ac2664b6419ff66f6e8b9669a0");

    private final static byte[] SSH_ECDSA_SIGNATURE = Hex.decodeHexOrFail(
            "00000013" +
                    "65636473612d736861322d6e6973747032" +
                    "3536" +
                    "0000004a" +
                    "00000021" +
                    "00949fa9151d71495d9c020635dcedac6a" +
                    "8665d079b4f721b05a9408771e455fe2" +
                    "00000021" +
                    "00df9c7a5ae59e5d2e42d3767e1525c825" +
                    "7cff82ac2664b6419ff66f6e8b9669a0"
    );

    private final static byte[] RAW_RSA_SIGNATURE_SHA512 = Hex.decodeHexOrFail(
            "4aef4be2d8edaed6faf2798c28685970" +
                    "ef19528e534ab3961d4e1b86ce5cf52a" +
                    "2bc7008d5e6738783d799779daf23714" +
                    "d688761ddf537eae9edab5a3a6b4e913" +
                    "04b7c2ed434c0a9ebbe3ea747a8c9b89" +
                    "e1cfc44007c1a12a6f4401e951c4b1ac" +
                    "9add2f49251f12effa31540448d12fec" +
                    "70188e4844597d73af3fbf9cca65d182" +
                    "1809f4c41a453e01a2f86bedcc691ec0" +
                    "831ec0fa6af47927f60b2559c2d95235" +
                    "0ad91d12cd94acb44f33e6039de00368" +
                    "8a729ccc045a367108af4fa89d8ae049" +
                    "e5c75872ee6ff30d7edf7fea2fcf7fca" +
                    "88aab94388b752abbab04b937ad77282" +
                    "a8a15c20005cf24f4b5d9174955a7e86" +
                    "6214a25f7f66d39ef31a6503da43d5dc"
    );

    private final static byte[] SSH_RSA_SIGNATURE_SHA512 = Hex.decodeHexOrFail(
            "0000000c7273612d736861322d353132" +
                    "000001004aef4be2d8edaed6faf2798c" +
                    "28685970ef19528e534ab3961d4e1b86" +
                    "ce5cf52a2bc7008d5e6738783d799779" +
                    "daf23714d688761ddf537eae9edab5a3" +
                    "a6b4e91304b7c2ed434c0a9ebbe3ea74" +
                    "7a8c9b89e1cfc44007c1a12a6f4401e9" +
                    "51c4b1ac9add2f49251f12effa315404" +
                    "48d12fec70188e4844597d73af3fbf9c" +
                    "ca65d1821809f4c41a453e01a2f86bed" +
                    "cc691ec0831ec0fa6af47927f60b2559" +
                    "c2d952350ad91d12cd94acb44f33e603" +
                    "9de003688a729ccc045a367108af4fa8" +
                    "9d8ae049e5c75872ee6ff30d7edf7fea" +
                    "2fcf7fca88aab94388b752abbab04b93" +
                    "7ad77282a8a15c20005cf24f4b5d9174" +
                    "955a7e866214a25f7f66d39ef31a6503" +
                    "da43d5dc"
    );

    private final static byte[] RAW_RSA_SIGNATURE_SHA256 = Hex.decodeHexOrFail(
            "904abb6965d075584d03e3d31aec58bc" +
                    "3738388b199c6aef55ec7e7f18daeaff" +
                    "6ff41d0e5dbd47c3a4cceb4a59d24cdb" +
                    "3d0041bc64324ae9e955232fb788f180" +
                    "ed885814760e18f73572cdf15a0fcc3b" +
                    "05c534e110e75a2093d27c96a8d122f3" +
                    "b30590003c5d90fd8029ab940d4ce3cf" +
                    "6cdeac92490cc0c93fbc9998e1d1fd31" +
                    "b2478f8cdf0e3af80a570212aa06bc7d" +
                    "d92af482e8826bae92bb4df637d073bd" +
                    "75647911981051d8e146a2ceffa86f02" +
                    "3ccd5746525e9599f215bcd3940e980a" +
                    "9190b435bd308b464e9799f3c186beee" +
                    "d5536f577e21177405059ebc2fe7bb43" +
                    "d014a96bd1221fbc821a7f5fda223d5d" +
                    "1be231260b237f88ef89738891e7c768"
    );

    private final static byte[] SSH_RSA_SIGNATURE_SHA256 = Hex.decodeHexOrFail(
            "0000000c7273612d736861322d323536" +
                    "00000100904abb6965d075584d03e3d3" +
                    "1aec58bc3738388b199c6aef55ec7e7f" +
                    "18daeaff6ff41d0e5dbd47c3a4cceb4a" +
                    "59d24cdb3d0041bc64324ae9e955232f" +
                    "b788f180ed885814760e18f73572cdf1" +
                    "5a0fcc3b05c534e110e75a2093d27c96" +
                    "a8d122f3b30590003c5d90fd8029ab94" +
                    "0d4ce3cf6cdeac92490cc0c93fbc9998" +
                    "e1d1fd31b2478f8cdf0e3af80a570212" +
                    "aa06bc7dd92af482e8826bae92bb4df6" +
                    "37d073bd75647911981051d8e146a2ce" +
                    "ffa86f023ccd5746525e9599f215bcd3" +
                    "940e980a9190b435bd308b464e9799f3" +
                    "c186beeed5536f577e21177405059ebc" +
                    "2fe7bb43d014a96bd1221fbc821a7f5f" +
                    "da223d5d1be231260b237f88ef897388" +
                    "91e7c768"
    );

    private final static byte[] RAW_RSA_SIGNATURE_SHA1 = Hex.decodeHexOrFail(
            "1c975c37a4137e9c861d20d9d40b6db16d" +
                    "1da8b17e360311b6a4ebcb3f1ff51d4906" +
                    "28b80de0dece08a1b5ebe8a5894ea2fea7" +
                    "40741e7c83c241a0d2bd9bdb3a2f3942ca" +
                    "e8ccc3bda7a17b40b00a0e214a5da76542" +
                    "11f5fc49b45d16b1e46fa80ce777969c51" +
                    "9f09bb45e312e4109b3af0c3133ffa221d" +
                    "a9e3c9e03fa2fdb70df03e6c83ee71f106" +
                    "b8f24fd72bad5e4e68123dda656ddba8ee" +
                    "11f9106154d1e1370bff3ba22e3c25b7d9" +
                    "334d903e4dd79a7389da41e9437e79ddd8" +
                    "a3335d2c217f01059bde2f3450f8933f38" +
                    "be10cd59467e9c9332c7794ccb9d19cb65" +
                    "a179b0166cd0e583e17f8f312222259ae3" +
                    "1b13e61fcae4da5c5554e2355218a0eb07" +
                    "19"
    );

    private final static byte[] SSH_RSA_SIGNATURE_SHA1 = Hex.decodeHexOrFail(
            "00000007" +
                    "7373682d727361" +
                    "00000100" +
                    "1c975c37a4137e9c861d20d9d40b6db16d" +
                    "1da8b17e360311b6a4ebcb3f1ff51d4906" +
                    "28b80de0dece08a1b5ebe8a5894ea2fea7" +
                    "40741e7c83c241a0d2bd9bdb3a2f3942ca" +
                    "e8ccc3bda7a17b40b00a0e214a5da76542" +
                    "11f5fc49b45d16b1e46fa80ce777969c51" +
                    "9f09bb45e312e4109b3af0c3133ffa221d" +
                    "a9e3c9e03fa2fdb70df03e6c83ee71f106" +
                    "b8f24fd72bad5e4e68123dda656ddba8ee" +
                    "11f9106154d1e1370bff3ba22e3c25b7d9" +
                    "334d903e4dd79a7389da41e9437e79ddd8" +
                    "a3335d2c217f01059bde2f3450f8933f38" +
                    "be10cd59467e9c9332c7794ccb9d19cb65" +
                    "a179b0166cd0e583e17f8f312222259ae3" +
                    "1b13e61fcae4da5c5554e2355218a0eb07" +
                    "19"
    );

    private final static byte[] RAW_EDDSA_SIGNATURE = Hex.decodeHexOrFail(
            "554946e827c6fd4b21b7a81a977a745331" +
                    "0e18c005403bfa4ddd87158b56b140fd61" +
                    "0bf15d7f38a32b55713fd38087ac8612dc" +
                    "1456cec315e4643b6d2489070a"
    );

    private final static byte[] SSH_EDDSA_SIGNATURE = Hex.decodeHexOrFail(
            "0000000b" +
                    "7373682d65643235353139" +
                    "00000040" +
                    "554946e827c6fd4b21b7a81a977a745331" +
                    "0e18c005403bfa4ddd87158b56b140fd61" +
                    "0bf15d7f38a32b55713fd38087ac8612dc" +
                    "1456cec315e4643b6d2489070a"
    );

    private final static byte[] ECDSA_PUBLIC = Hex.decodeHexOrFail(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004aa0d448dd43f1cae67af7a497cff4aab13ac7" +
                    "9dc32c31881f92911ed8a60c1cb349e9ebe4758910a6f7244c7a25bcc7cc726e168506ceaf69ea26a7c6468a46e"
    );
    private final static byte[] ECDSA_PRIVATE = Hex.decodeHexOrFail(
            "3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101" +
                    "04204d09d2830a84fe757fc14dd945d8193b015b53fb41f842ebc5efc478780a7419"
    );

    private final static byte[] RSA_PUBLIC = Hex.decodeHexOrFail(
            "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b0536771ab357106e33d68599d" +
                    "73f004793b9c0efd693a219136869da721a84d41f813734ee4b7e34bd52757e36b289636f6b1b77096867e7bbd" +
                    "5100b0e9c8c5e4842bae1915694f753be3f8d5f7bf97c3189faa6e5febecd8c5dc06e73f442046b05d831d27e3" +
                    "3bab874ec5cabc8fa0ae5b5a700b493a0a5498d0efc46283c6f09a02fa4cd23a5cdd120d16f8da94b1e24f1cc4" +
                    "3c39c412100687a00dd79fec1454faf5834d0caa9d74bdec08fe746e6f63127008822de32672fde3b6992e179d" +
                    "860b050b12a58293597d4330b6e5eb80383f819c39dd11cc9565eda9bf74c3d635c38850b50e9d18d70281fd59" +
                    "4a4dc6c99dced5a57e9d5a214680b75d36590203010001");
    private final static byte[] RSA_PRIVATE = Hex.decodeHexOrFail(
            "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100b0536771ab357106" +
                    "e33d68599d73f004793b9c0efd693a219136869da721a84d41f813734ee4b7e34bd52757e36b289636f6b1b770" +
                    "96867e7bbd5100b0e9c8c5e4842bae1915694f753be3f8d5f7bf97c3189faa6e5febecd8c5dc06e73f442046b0" +
                    "5d831d27e33bab874ec5cabc8fa0ae5b5a700b493a0a5498d0efc46283c6f09a02fa4cd23a5cdd120d16f8da94" +
                    "b1e24f1cc43c39c412100687a00dd79fec1454faf5834d0caa9d74bdec08fe746e6f63127008822de32672fde3" +
                    "b6992e179d860b050b12a58293597d4330b6e5eb80383f819c39dd11cc9565eda9bf74c3d635c38850b50e9d18" +
                    "d70281fd594a4dc6c99dced5a57e9d5a214680b75d3659020301000102820100288a449261e6dba1d5c55ca49e" +
                    "0af5f851575f3e230d7a8c153310285730e9dd3979ac1f2ad8735f132462f3561a612e885c97e7b13f2a951226" +
                    "28e59bc7649dfb385842a309c538bb9f957eb4d34d7dbb2182345144449e2408f9d9ac796354786c3c53d4f442" +
                    "ce895586cafb1df777de1eaae06ff7da1c5deef4baebd02ab3c50a9d5d7589734a0bb6b28c605840df9347a924" +
                    "96d393dd627a45c56634f1fa1aa70b18162b5a24220c30ed945fcae0a113be4c54efd61f5cc69ea6b0fae29a10" +
                    "9c28cbb41af2d405279c64e7f2ab888f42f20526074daedc72b583a44727c53ced7529ecc025949e2b5c2b732a" +
                    "3fc263b4e61b97813ff447457b4d23d8fbf102818100da242c438d437d5f2192f9fe1ca6b22311d9cc378ffe5a" +
                    "2f31dd50d75f3aa72402d597646b6d4d5fdeed723fb7c501a98bb912f1852775e6eab3c72eae1cdd7dad704ff7" +
                    "63e3e07689585e9bb4a7f3d8e3e09f41bfda1c1afd4db0ed1ed9eb40ec917e0ed46a628f66c19ccd5bc74fa025" +
                    "38958326a2ecd98861bbdfd0671b5302818100ceed67ab13fb0cd9de01b874c24cbcb53552607293c39ff70300" +
                    "1846ad7c6aa0d875fb2113775b899a4d128ecd16f025415f63de24d234b3f1b4d365bb53692fa9fb56bfb072ad" +
                    "afd1cf136eaa586aea891e50ab1941db5cfbb2c6c46fcd35083c4d2e4fa890c407a6cd867b5a74e9451eb0bcfd" +
                    "3b65ef1d32b1f95b42545e230281806ec287271586fb155e7abe2c6467cf7337111b3beb04fecd8fc80bd00f2e" +
                    "3cc77018fb71a58a2e0b4ba9cca4c5ae6615ac3820823955bbebafa7f0aea701490513173fc321190753a89112" +
                    "188535f1fe62561f06c75efb7e48b735ea700bbe038d1aa2a2ecffc763808d360c9f5927f8ec6d3a9d08f518c5" +
                    "ab15d4cae38a36b9028181009557ac0141ab67cbf9b95e2a0e6d19a8e2b1f05fe11b47e11b6e3f170b7086f84d" +
                    "21613caef2eec2b1f53c168a182afb8861d30ee99e38614269d24452dd514610351097ca3e09f2a1c704ec52ce" +
                    "fb6307d13441383a5a9a9221a5e8f213b5599b43cccfbb05b8251992ada36b568360da548e216974190e069f82" +
                    "2b060523e702818100ce6cf2dd975ca5869d0cfd82e2d5fd6abcfe10a889dec6de18b7f2b6b0b4aafdb78c7503" +
                    "44de0471f1a80050c1b0c4865c1281b2a18be21f800f0e7027025c465a318436863f9a9a5f7f2e56272899bcee" +
                    "024d5f79aca5bbbdbf5e8790d13c128092431bfbeed641a2582eb7ed1a8f838e32d3fa17220ca8c3baffcffd08" +
                    "67de");

    private static final String ECDSA_OPENSSH_PUBLIC_B64 =
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKoNRI3UPxyuZ696SXz/" +
                    "SqsTrHncMsMYgfkpEe2KYMHLNJ6evkdYkQpvckTHolvMfMcm4WhQbOr2nqJqfGRopG4=";
    private static final String RSA_OPENSSH_PUBLIC_B64 =
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCwU2dxqzVxBuM9aFmdc/AEeTucDv1pOiGRNoadpyGo" +
                    "TUH4E3NO5LfjS9UnV+NrKJY29rG3cJaGfnu9UQCw6cjF5IQrrhkVaU91O+P41fe/l8MY" +
                    "n6puX+vs2MXcBuc/RCBGsF2DHSfjO6uHTsXKvI+grltacAtJOgpUmNDvxGKDxvCaAvpM" +
                    "0jpc3RINFvjalLHiTxzEPDnEEhAGh6AN15/sFFT69YNNDKqddL3sCP50bm9jEnAIgi3j" +
                    "JnL947aZLhedhgsFCxKlgpNZfUMwtuXrgDg/gZw53RHMlWXtqb90w9Y1w4hQtQ6dGNcC" +
                    "gf1ZSk3GyZ3O1aV+nVohRoC3XTZZ";

    @Test
    public void testEcDsa() throws Exception {
        byte[] out = SshUtil.encodeSshSignature("ecdsa-sha2-nistp256", RAW_ECDSA_SIGNATURE);

        Assert.assertArrayEquals(SSH_ECDSA_SIGNATURE, out);
    }

    @Test
    public void testRsaSha1() throws Exception {
        byte[] out = SshUtil.encodeSshSignature("ssh-rsa", RAW_RSA_SIGNATURE_SHA1);

        Assert.assertArrayEquals(SSH_RSA_SIGNATURE_SHA1, out);
    }

    @Test
    public void testRsaSha256() throws Exception {
        byte[] out = SshUtil.encodeSshSignature("rsa-sha2-256", RAW_RSA_SIGNATURE_SHA256);

        Assert.assertArrayEquals(SSH_RSA_SIGNATURE_SHA256, out);
    }

    @Test
    public void testRsaSha512() throws Exception {
        byte[] out = SshUtil.encodeSshSignature("rsa-sha2-512", RAW_RSA_SIGNATURE_SHA512);

        Assert.assertArrayEquals(SSH_RSA_SIGNATURE_SHA512, out);
    }

    @Test
    public void testEdDsa() throws Exception {
        byte[] out = SshUtil.encodeSshSignature("ssh-ed25519", RAW_EDDSA_SIGNATURE);

        Assert.assertArrayEquals(SSH_EDDSA_SIGNATURE, out);
    }

    @Test
    public void encodeEcPublicKey() throws Exception {
        ECPublicKey ecPublicKey = JcaTestUtils.parseEcPublicKey(ECDSA_PUBLIC);
        byte[] encodedKey = SshUtil.encodeEcPublicKey(SECObjectIdentifiers.secp256r1, ecPublicKey);
        Assert.assertArrayEquals(Base64.decode(ECDSA_OPENSSH_PUBLIC_B64), encodedKey);
    }

    @Test
    public void encodeRsaPublicKeyBytes() throws Exception {
        RSAPublicKey rsaPublicKey = JcaTestUtils.parseRsaPublicKey(RSA_PUBLIC);
        byte[] encodedKey = SshUtil.encodeRsaPublicKey(rsaPublicKey);
        Assert.assertArrayEquals(Base64.decode(RSA_OPENSSH_PUBLIC_B64), encodedKey);
    }
}