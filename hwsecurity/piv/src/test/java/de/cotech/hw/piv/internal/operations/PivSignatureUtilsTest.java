package de.cotech.hw.piv.internal.operations;

import de.cotech.hw.util.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("WeakerAccess")
public class PivSignatureUtilsTest {

    static final int PADDING_BLOCK_SIZE = 256;
    static final byte[] DIGEST = Hex.decodeHexOrFail("1a2b3c4d");
    static final byte[] DIGEST_PADDED = Hex.decodeHexOrFail("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001a2b3c4d");

    PivSignatureUtils pivSignatureUtils = PivSignatureUtils.getInstance();

    @Test
    public void pkcs1Pad() {
        byte[] encodedDigest = pivSignatureUtils.pkcs1Pad(DIGEST, PADDING_BLOCK_SIZE);

        assertEquals(PADDING_BLOCK_SIZE, encodedDigest.length);
        assertArrayEquals(DIGEST_PADDED, encodedDigest);
    }
}