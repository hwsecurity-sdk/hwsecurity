package de.cotech.hw.fido2.internal.cose;


import de.cotech.hw.util.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;


public class CosePublicKeyUtilsTest {

    private static final byte[] PUBLIC_KEY_X9_62 = Hex.decodeHexOrFail(
            "04a64c3f0601c440ce2061186419804fa5c2d505be6976822f8190602ffd125613da39ab5e4079338052a33bd4f05f2b9ce176b2df607e45a93405e77eabb2f1db");
    private static final byte[] PUBLIC_KEY_COSE = Hex.decodeHexOrFail(
            "a5010203262001215820a64c3f0601c440ce2061186419804fa5c2d505be6976822f8190602ffd125613225820da39ab5e4079338052a33bd4f05f2b9ce176b2df607e45a93405e77eabb2f1db");

    @Test
    public void encodex9PublicKeyAsCose() throws Exception {
        byte[] coseEncodedKey = CosePublicKeyUtils.encodex962PublicKeyAsCose(PUBLIC_KEY_X9_62);
        assertArrayEquals(PUBLIC_KEY_COSE, coseEncodedKey);
    }

    @Test
    public void encodeCosePublicKeyAsX9() throws Exception {
        byte[] x9EncodedKey = CosePublicKeyUtils.encodeCosePublicKeyAsX962(PUBLIC_KEY_COSE);
        assertArrayEquals(PUBLIC_KEY_X9_62, x9EncodedKey);
    }
}