package de.cotech.hw.fido2.internal.pinauth;


import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

import de.cotech.hw.fido2.internal.cose.CosePublicKeyUtils;
import de.cotech.hw.fido2.internal.crypto.P256;
import de.cotech.hw.util.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;


@SuppressWarnings("WeakerAccess")
public class PinAuthCryptoUtilTest {
    static final Provider PROVIDER = new BouncyCastleProvider();

    static final byte[] EC_PRIV = Hex.decodeHexOrFail("7452E599FEE739D8A653F6A507343D12D382249108A651402520B72F24FE7684");
    static final byte[] EC_PUB = Hex.decodeHexOrFail("0444D78D7989B97E62EA993496C9EF6E8FD58B8B00715F9A89153DDD9C4657E47FEC802EE7D22BD4E100F12E48537EB4E7E96ED3A47A0A3BD5F5EEAB65001664F9");
    static final byte[] DEV_PUB = Hex.decodeHexOrFail("040501D5BC78DA9252560A26CB08FCC60CBE0B6D3B8E1D1FCEE514FAC0AF675168D551B3ED46F665731F95B4532939C25D91DB7EB844BD96D4ABD4083785F8DF47");
    static final byte[] SHARED = Hex.decodeHexOrFail("c42a039d548100dfba521e487debcbbb8b66bb7496f8b1862a7a395ed83e1a1c");
    static final byte[] PIN_HASH = Hex.decodeHexOrFail("03ac674216f3e15c761ee1a5e255f067");
    static final byte[] PIN_HASH_ENC = Hex.decodeHexOrFail("afe8327ce416da8ee3d057589c2ce1a9");
    static final byte[] TOKEN_ENC = Hex.decodeHexOrFail("7A9F98E31B77BE90F9C64D12E9635040");
    static final byte[] TOKEN = Hex.decodeHexOrFail("aff12c6dcfbf9df52f7a09211e8865cd");
    static final String PADDED_PIN_1234 = "31323334000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    private final PinAuthCryptoUtil pinAuthCryptoUtil = new PinAuthCryptoUtil();

    @Test
    public void calculatePinHashEnc() throws Exception {
        byte[] pinHashEnc = pinAuthCryptoUtil.calculatePinHashEnc(SHARED, "1234");
        assertArrayEquals(PIN_HASH_ENC, pinHashEnc);
    }

    @Test
    public void calculatePinHash() throws Exception {
        byte[] pinHash = pinAuthCryptoUtil.calculatePinHash("1234");
        assertArrayEquals(PIN_HASH, pinHash);
    }

    @Test
    public void padPin() throws IOException {
        byte[] paddedPin = pinAuthCryptoUtil.padPin("1234");
        assertEquals(PADDED_PIN_1234, Hex.encodeHexString(paddedPin));
    }

    @Test
    public void decryptPinToken() throws Exception {
        byte[] pinToken = pinAuthCryptoUtil.decryptPinToken(SHARED, TOKEN_ENC);
        assertArrayEquals(TOKEN, pinToken);
    }

    @Test
    public void publicKeyFromCosePublicKey_to_cosePublicKeyFromPublicKey() throws IOException {
        byte[] cosePublicKey = CosePublicKeyUtils.encodex962PublicKeyAsCose(EC_PUB);

        PublicKey publicKey = pinAuthCryptoUtil.publicKeyFromCosePublicKey(cosePublicKey);
        byte[] cosePublicKey2 = pinAuthCryptoUtil.cosePublicKeyFromPublicKey(publicKey);

        assertArrayEquals(cosePublicKey, cosePublicKey2);
    }

    @Test
    public void generateSharedSecret() throws Exception {
        PrivateKey platformPrivateKey = P256.deserializePrivateKey(EC_PRIV);

        byte[] cosePublicKey = CosePublicKeyUtils.encodex962PublicKeyAsCose(DEV_PUB);
        PublicKey authenticatorPublicKey = pinAuthCryptoUtil.publicKeyFromCosePublicKey(cosePublicKey);

        byte[] secret = pinAuthCryptoUtil.generateSharedSecret(platformPrivateKey, authenticatorPublicKey);

        assertArrayEquals(secret, SHARED);
    }
}