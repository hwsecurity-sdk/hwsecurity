package de.cotech.hw.fido2.internal.pinauth;


import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import de.cotech.hw.fido2.exceptions.FidoClientPinBlockedException;
import de.cotech.hw.fido2.exceptions.FidoClientPinInvalidException;
import de.cotech.hw.fido2.exceptions.FidoClientPinLastAttemptException;
import de.cotech.hw.fido2.internal.FakeFido2AppletConnection;
import de.cotech.hw.util.Hex;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertSame;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@SuppressWarnings("WeakerAccess")
public class PinProtocolV1Test {
    static final String CLIENT_PIN_GET_RETRIES = "801000000606a201010201";
    static final String CLIENT_PIN_GET_RETRIES_RESPONSE_EIGHT = "00a103089000";
    static final String CLIENT_PIN_GET_RETRIES_RESPONSE_ONE = "00a103019000";
    static final String CLIENT_PIN_GET_RETRIES_RESPONSE_ZERO = "00a103009000";
    static final String CLIENT_PIN_GET_AGREEMENT = "801000000606a201010202";
    static final String CLIENT_PIN_GET_RESPONSE = "00a101a501020338182001215820f370174f29f360cff04035c4b46daf2a93468398521ac7fc7bf8f8f986d9e08f2258202ba85af4992d37ef3977eea283b65a00e7c06dc473aeecc24b70f9b9d22d5e8d9000";
    static final byte[] AUTHENTICATOR_KEY_AGREEMENT = Hex.decodeHexOrFail(
            "a501020338182001215820f370174f29f360cff04035c4b46daf2a93468398521ac7fc7bf8f8f986d9e08f2258202ba85af4992d37ef3977eea283b65a00e7c06dc473aeecc24b70f9b9d22d5e8d");
    static final byte[] PLATFORM_KEY_AGREEMENT = Hex.decodeHexOrFail(
            "a501020326200121582099401f6ffa9446585074d1058578f4c68ab46953ccf8cb7910d8b3c9350e1040225820a3c962cddad166b1fdea8a95a377dbf8efbedd82778a8004b884f0009bd6df9506");
    static final byte[] PIN_HASH_ENC = Hex.decodeHexOrFail("2eb756ae474f7ca032b5111b2eef6959");
    static final byte[] PIN_TOKEN_ENC = Hex.decodeHexOrFail("554df3802226935b2bf49f30aae3096f");
    static final String CLIENT_PIN_GET_TOKEN = "801000006606a40101020503a501020326200121582099401f6ffa9446585074d1058578f4c68ab46953ccf8cb7910d8b3c9350e1040225820a3c962cddad166b1fdea8a95a377dbf8efbedd82778a8004b884f0009bd6df9506502eb756ae474f7ca032b5111b2eef6959";
    static final String CLIENT_PIN_GET_TOKEN_RESPONSE = "00a10250554df3802226935b2bf49f30aae3096f9000";
    static final String CLIENT_PIN_GET_TOKEN_RESPONSE_INVALID = "329000";
    static final String CLIENT_PIN_GET_TOKEN_RESPONSE_BLOCKED = "319000";

    static final byte[] SHARED_SECRET = new byte[1];
    static final byte[] PIN_TOKEN = new byte[1];

    private FakeFido2AppletConnection fakeFidoConnection;

    @Before
    public void setup() throws Exception {
        fakeFidoConnection = FakeFido2AppletConnection.create(false);
    }

    @Test
    public void pinAuth() throws Exception {
        PinProtocolV1 pinProtocolV1 = setupPinProtocol();

        fakeFidoConnection.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_EIGHT);
        fakeFidoConnection.expect(CLIENT_PIN_GET_AGREEMENT, CLIENT_PIN_GET_RESPONSE);
        fakeFidoConnection.expect(CLIENT_PIN_GET_TOKEN, CLIENT_PIN_GET_TOKEN_RESPONSE);

        PinToken pinToken = pinProtocolV1.clientPinAuthenticate(fakeFidoConnection.connection, "1234", false);

        assertSame(PIN_TOKEN, pinToken.pinToken());
        fakeFidoConnection.verify();
    }

    @Test(expected = FidoClientPinInvalidException.class)
    public void pinAuth_invalid() throws Exception {
        PinProtocolV1 pinProtocolV1 = setupPinProtocol();

        fakeFidoConnection.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_EIGHT);
        fakeFidoConnection.expect(CLIENT_PIN_GET_AGREEMENT, CLIENT_PIN_GET_RESPONSE);
        fakeFidoConnection.expect(CLIENT_PIN_GET_TOKEN, CLIENT_PIN_GET_TOKEN_RESPONSE_INVALID);

        pinProtocolV1.clientPinAuthenticate(fakeFidoConnection.connection, "1234", false);
    }

    @Test(expected = FidoClientPinInvalidException.class)
    public void pinAuth_invalid_blocked() throws Exception {
        PinProtocolV1 pinProtocolV1 = setupPinProtocol();

        fakeFidoConnection.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_ONE);
        fakeFidoConnection.expect(CLIENT_PIN_GET_AGREEMENT, CLIENT_PIN_GET_RESPONSE);
        fakeFidoConnection.expect(CLIENT_PIN_GET_TOKEN, CLIENT_PIN_GET_TOKEN_RESPONSE_BLOCKED);

        pinProtocolV1.clientPinAuthenticate(fakeFidoConnection.connection, "1234", true);
    }

    @Test(expected = FidoClientPinLastAttemptException.class)
    public void pinAuth_lastAttempt_fail() throws Exception {
        PinProtocolV1 pinProtocolV1 = setupPinProtocol();

        fakeFidoConnection.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_ONE);

        pinProtocolV1.clientPinAuthenticate(fakeFidoConnection.connection, "1234", false);
    }

    @Test
    public void pinAuth_lastAttempt_ok() throws Exception {
        PinProtocolV1 pinProtocolV1 = setupPinProtocol();

        fakeFidoConnection.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_ONE);
        fakeFidoConnection.expect(CLIENT_PIN_GET_AGREEMENT, CLIENT_PIN_GET_RESPONSE);
        fakeFidoConnection.expect(CLIENT_PIN_GET_TOKEN, CLIENT_PIN_GET_TOKEN_RESPONSE);

        PinToken pinToken = pinProtocolV1.clientPinAuthenticate(fakeFidoConnection.connection, "1234", true);

        assertSame(PIN_TOKEN, pinToken.pinToken());
        fakeFidoConnection.verify();
    }

    @Test(expected = FidoClientPinBlockedException.class)
    public void pinAuth_blocked() throws Exception {
        PinProtocolV1 pinProtocolV1 = setupPinProtocol();

        fakeFidoConnection.expect(CLIENT_PIN_GET_RETRIES, CLIENT_PIN_GET_RETRIES_RESPONSE_ZERO);

        pinProtocolV1.clientPinAuthenticate(fakeFidoConnection.connection, "1234", true);

    }

    private PinProtocolV1 setupPinProtocol() throws IOException {
        PinAuthCryptoUtil pinAuthCryptoUtil = mock(PinAuthCryptoUtil.class);
        PinProtocolV1 pinProtocolV1 = new PinProtocolV1(pinAuthCryptoUtil);

        // These values are opaque to PinProtocolV1. we just generate empty mock objects for them
        PublicKey publicKey = mock(PublicKey.class);
        PrivateKey privateKey = mock(PrivateKey.class);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        PublicKey authenticatorPublicKey = mock(PublicKey.class);

        when(pinAuthCryptoUtil.generatePlatformKeyPair()).thenReturn(keyPair);
        when(pinAuthCryptoUtil.cosePublicKeyFromPublicKey(publicKey))
                .thenReturn(PLATFORM_KEY_AGREEMENT);
        when(pinAuthCryptoUtil.publicKeyFromCosePublicKey(aryEq(AUTHENTICATOR_KEY_AGREEMENT)))
                .thenReturn(authenticatorPublicKey);
        when(pinAuthCryptoUtil.calculatePinHashEnc(aryEq(SHARED_SECRET), eq("1234")))
                .thenReturn(PIN_HASH_ENC);
        when(pinAuthCryptoUtil.generateSharedSecret(privateKey, authenticatorPublicKey))
                .thenReturn(SHARED_SECRET);
        when(pinAuthCryptoUtil.decryptPinToken(SHARED_SECRET, PIN_TOKEN_ENC)).thenReturn(PIN_TOKEN);
        return pinProtocolV1;
    }
}