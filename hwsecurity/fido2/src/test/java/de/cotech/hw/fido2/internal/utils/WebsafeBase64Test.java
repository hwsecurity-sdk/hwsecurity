package de.cotech.hw.fido2.internal.utils;


import android.util.Base64;

import de.cotech.hw.util.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static org.junit.Assert.*;


@SuppressWarnings("WeakerAccess")
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 24)
public class WebsafeBase64Test {
    static final byte[] DECODED_HEX = Hex.decodeHexOrFail("18dc5f5507c454ea22f6e5355bf8ccfb");
    static final byte[] DECODED = Hex.decodeHexOrFail("18dc5f5507c454ea22f6e5355bf8ccfb");
    static final String ENCODED_WB64 = "GNxfVQfEVOoi9uU1W_jM-w";
    static final String ENCODED_B64 = "GNxfVQfEVOoi9uU1W/jM+w";

    @Test
    public void encodeToString() {
        String encoded = WebsafeBase64.encodeToString(DECODED);
        assertEquals(ENCODED_WB64, encoded);
    }

    @Test
    public void decode_websafe() {
        byte[] decoded = WebsafeBase64.decode(ENCODED_WB64);
        assertArrayEquals(DECODED, decoded);
    }

    @Test
    public void decode_default() {
        byte[] decoded = Base64.decode(ENCODED_B64, Base64.DEFAULT);
        assertArrayEquals(DECODED, decoded);
    }
}