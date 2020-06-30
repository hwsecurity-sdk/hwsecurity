package de.cotech.hw.fido2.internal.webauthn;


import de.cotech.hw.fido2.domain.create.AuthenticatorData;
import de.cotech.hw.util.Hex;
import org.junit.Assert;
import org.junit.Test;


@SuppressWarnings("WeakerAccess")
public class AuthenticatorDataParserTest {

    static final String DATA_HEX = "964491febf301ee4bcb88cb5dc1fa95df27f1643a0c7cef9f71ceef6689e067a41000001408876631bd4a0427f57730ec71c9e027900462a858dfaa38c5b6b20272b8f457cd2f6affe19fa39314260d4487c63f1b3c1dcdb7a964491febf301ee4bcb88cb5dc1fa95df27f1643a0c7cef9f71ceef6689e067a40010000a50102032620012158208a649c9f8a7ccf6e11ebec5753ec6edf42f8ac6565c44fab0a87cb180d981b972258207111ab96f3bf664405025f74509bc689e4686a9ec9ba94c5684ac98b9a5257a2";
    static final byte[] DATA = Hex.decodeHexOrFail(DATA_HEX);

    static final String DATA_SHORT_HEX = "1194228da8fdbdeefd261bd7b6595cfd70a50d70c6407bcf013de96d4efb17de010000003b";
    static final byte[] DATA_SHORT = Hex.decodeHexOrFail(DATA_SHORT_HEX);

    AuthenticatorDataParser parser = new AuthenticatorDataParser();

    @Test
    public void decode_encode_short() throws Exception {
        AuthenticatorData authenticatorData = parser.fromBytes(DATA_SHORT);
        byte[] bytes = parser.toBytes(authenticatorData);
        Assert.assertEquals(DATA_SHORT_HEX, Hex.encodeHexString(bytes));
    }

    @Test
    public void decode_encode() throws Exception {
        AuthenticatorData authenticatorData = parser.fromBytes(DATA);
        byte[] bytes = parser.toBytes(authenticatorData);
        Assert.assertEquals(DATA_HEX, Hex.encodeHexString(bytes));
    }

    @Test
    public void decode_anonymize_encode() throws Exception {
        AuthenticatorData authenticatorData = parser.fromBytes(DATA);
        String hexAaguid = Hex.encodeHexString(authenticatorData.attestedCredentialData().aaguid());
        // noinspection ReplaceAllDot, yes this is what we want
        String hexAaguidAnonymized = hexAaguid.replaceAll(".", "0");
        String expectedHex = DATA_HEX.replace(hexAaguid, hexAaguidAnonymized);

        AuthenticatorData anonymizedAuthenticatorData = authenticatorData.withEmptyAaguid();
        byte[] bytes = parser.toBytes(anonymizedAuthenticatorData);

        Assert.assertEquals(expectedHex, Hex.encodeHexString(bytes));
    }
}
