package de.cotech.hw.fido2.internal.utils;


import java.nio.ByteBuffer;

import de.cotech.hw.fido2.internal.utils.DerUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import static org.junit.Assert.assertEquals;


public class DerUtilsTest {
    private static final byte[] DATA = Base64.decode("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUASUVlTkm9TXaTahsccnT9CpKaY1Nhlel0mx/wXoIP+uap0V6nXMrLHyUSv3OT2GxoOKU5kZqTeODCymQiMrVrpEd5q7aqACTdpjN0QBZz1YV2uY2LzDyzLCKt9Ey6ut");

    @Test
    public void findDerEncodedLength() throws Exception {
        int derEncodedLength = DerUtils.findDerEncodedLength(ByteBuffer.wrap(DATA));

        assertEquals(DATA.length, derEncodedLength);
    }
}