package de.cotech.hw.fido2.internal.jsapi;


import de.cotech.hw.fido2.domain.create.PublicKeyCredentialCreationOptions;
import de.cotech.hw.fido2.internal.json.JsonWebauthnOptionsParser;
import de.cotech.hw.util.Hex;
import org.json.JSONException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;


@RunWith(RobolectricTestRunner.class)
public class JsonWebauthnOptionsParserTest {
    private JsonWebauthnOptionsParser parser = new JsonWebauthnOptionsParser();

    @Test
    public void fromJsonMakeCredential() throws JSONException {
        String x = "{\"publicKey\":{\"challenge\":{\"0\":219,\"1\":30,\"2\":239,\"3\":9,\"4\":130,\"5\":70,\"6\":62,\"7\":3,\"8\":35,\"9\":154,\"10\":109,\"11\":159,\"12\":150,\"13\":76,\"14\":216,\"15\":63},\"rp\":{\"name\":\"Acme\"},\"user\":{\"id\":{\"0\":49,\"1\":48,\"2\":57,\"3\":56,\"4\":50,\"5\":51,\"6\":55,\"7\":50,\"8\":51,\"9\":53,\"10\":52,\"11\":48,\"12\":57,\"13\":56,\"14\":55,\"15\":50},\"name\":\"john.p.smith@example.com\",\"displayName\":\"John P. Smith\",\"icon\":\"https://pics.acme.com/00/p/aBjjjpqPb.png\"},\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"}],\"authenticatorSelection\":{\"authenticatorAttachment\":\"cross-platform\",\"requireResidentKey\":false,\"userVerification\":\"preferred\"},\"timeout\":60000,\"excludeCredentials\":[],\"extensions\":{\"exts\":true}}}\n";

        PublicKeyCredentialCreationOptions authenticatorMakeCredential =
                parser.fromOptionsJsonMakeCredential(x);

        // test data from https://webauthn.hwsecurity.dev/driver.js
        assertEquals("john.p.smith@example.com", authenticatorMakeCredential.user().name());
        assertEquals("John P. Smith", authenticatorMakeCredential.user().displayName());
        assertEquals("https://pics.acme.com/00/p/aBjjjpqPb.png", authenticatorMakeCredential.user().icon());
        assertEquals(Hex.encodeHexString("1098237235409872".getBytes()), Hex.encodeHexString(authenticatorMakeCredential.user().id()));
        assertEquals("Acme", authenticatorMakeCredential.rp().name());
        assertNull(authenticatorMakeCredential.rp().id());
        assertNull(authenticatorMakeCredential.excludeCredentials());
    }
}