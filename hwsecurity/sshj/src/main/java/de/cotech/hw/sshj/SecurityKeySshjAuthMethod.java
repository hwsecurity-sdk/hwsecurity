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

package de.cotech.hw.sshj;


import com.hierynomus.sshj.key.KeyAlgorithm;
import com.hierynomus.sshj.signature.Ed25519PublicKey;

import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.signature.Signature;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.method.AbstractAuthMethod;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.util.HwTimber;
import de.cotech.hw.util.Hwsecurity25519PublicKey;

/**
 * Based on AuthPublickey and KeyedAuthMethod in SSHJ
 * https://github.com/hierynomus/sshj/tree/master/src/main/java/net/schmizz/sshj/userauth/method
 */
public class SecurityKeySshjAuthMethod extends AbstractAuthMethod {

    SecurityKeyAuthenticator securityKeyAuthenticator;
    PublicKey key;

    /**
     * Initialize this method with the provider for public and private key.
     */
    public SecurityKeySshjAuthMethod(SecurityKeyAuthenticator securityKeyAuthenticator) {
        super("publickey");
        this.securityKeyAuthenticator = securityKeyAuthenticator;
    }

    /**
     * Builds a feeler request (sans signature).
     */
    @Override
    protected SSHPacket buildReq() throws UserAuthException {
        return buildReq(false);
    }

    /**
     * Internal use.
     */
    @Override
    public void handle(Message cmd, SSHPacket buf) throws UserAuthException, TransportException {
        if (cmd == Message.USERAUTH_60)
            sendSignedReq();
        else
            super.handle(cmd, buf);
    }

    /**
     * Send SSH_MSG_USERAUTH_REQUEST containing the signature.
     *
     * @throws UserAuthException
     * @throws TransportException
     */
    private void sendSignedReq() throws UserAuthException, TransportException {
        HwTimber.d("Key acceptable, sending signed request");
        params.getTransport().write(putSig(buildReq(true)));
    }

    /**
     * Builds SSH_MSG_USERAUTH_REQUEST packet.
     *
     * @param signed whether the request packet will contain signature
     * @return the {@link SSHPacket} containing the request packet
     * @throws UserAuthException
     */
    private SSHPacket buildReq(boolean signed) throws UserAuthException {
        HwTimber.d("buildReq");
        return putPubKey(super.buildReq().putBoolean(signed));
    }

    protected SSHPacket putPubKey(SSHPacket reqBuf) throws UserAuthException {
        PublicKey key = retrievePublicKey();
        KeyType keyType = KeyType.fromKey(key);
        try {
            KeyAlgorithm ka = params.getTransport().getClientKeyAlgorithm(keyType);
            reqBuf.putString(ka.getKeyAlgorithm())
                    .putString(new Buffer.PlainBuffer().putPublicKey(key).getCompactData());
            return reqBuf;
        } catch (IOException ioe) {
            throw new UserAuthException("No KeyAlgorithm configured for key " + keyType);
        }
    }

    protected SSHPacket putSig(SSHPacket reqBuf) throws UserAuthException {
        PublicKey key = retrievePublicKey();
        final KeyType kt = KeyType.fromKey(key);
        Signature signature;
        try {
            signature = params.getTransport().getClientKeyAlgorithm(kt).newSignature();
        } catch (TransportException e) {
            throw new UserAuthException("No KeyAlgorithm configured for key " + kt);
        }

        byte[] challenge = new Buffer.PlainBuffer()
                .putString(params.getTransport().getSessionID())
                .putBuffer(reqBuf) // & rest of the data for sig
                .getCompactData();

        String hashAlgo = getSignatureHashAlgorithmName(signature.getSignatureName());

        try {
            byte[] signedChallenge = securityKeyAuthenticator.authenticateWithDigest(challenge, hashAlgo);
            reqBuf.putSignature(signature.getSignatureName(), signature.encode(signedChallenge));

            return reqBuf;
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new UserAuthException(e);
        }
    }

    private static String getSignatureHashAlgorithmName(String signatureName) throws UserAuthException {
        switch (signatureName) {
            // see net.schmizz.sshj.signature.SignatureRSA
            case "ssh-rsa":
                return "SHA-1";
            case "rsa-sha2-256":
                return "SHA-256";
            case "rsa-sha2-512":
                return "SHA-512";
            // see net.schmizz.sshj.signature.SignatureECDSA
            case "ecdsa-sha2-nistp256":
                return "SHA-256";
            case "ecdsa-sha2-nistp384":
                return "SHA-384";
            case "ecdsa-sha2-nistp521":
                return "SHA-512";
            // see com.hierynomus.sshj.signature.SignatureEdDSA
            case "ssh-ed25519":
                return "SHA-512";
            default:
                throw new UserAuthException("Unknown ssh algorithm " + signatureName);
        }
    }

    private PublicKey retrievePublicKey() throws UserAuthException {
        if (key != null) {
            return key;
        }
        try {
            key = securityKeyAuthenticator.retrievePublicKey();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting public key");
        }
        if (key instanceof Hwsecurity25519PublicKey) {
            HwTimber.d("Converting raw Ed25519 key to SSHJ's Ed25519PublicKey class.");
            EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName("Ed25519");
            EdDSAPublicKeySpec publicSpec = new EdDSAPublicKeySpec(key.getEncoded(), ed25519);
            key = new Ed25519PublicKey(publicSpec);
        }

        return key;
    }

}
