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

package de.cotech.hw.provider;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;


@SuppressWarnings("unused") // used by CotechSecurityKeyProvider
@RestrictTo(Scope.LIBRARY_GROUP)
public abstract class SecurityKeySignature extends SignatureSpi {
    private final MessageDigest md;
    private final ByteArrayOutputStream rawData;
    private final String algorithmName;
    private boolean digestReset;
    private SecurityKeyPrivateKey securityKeyPrivateKey;
    private String digestName;

    SecurityKeySignature(String algorithmName, String digestName) {
        try {
            this.algorithmName = algorithmName;
            this.digestName = digestName;
            if (digestName != null) {
                this.md = MessageDigest.getInstance(digestName);
                this.rawData = null;
            } else {
                this.md = null;
                this.rawData = new ByteArrayOutputStream();
            }
        } catch (NoSuchAlgorithmException var5) {
            throw new ProviderException(var5);
        }

        this.digestReset = true;
    }

    protected void engineInitVerify(PublicKey var1) {
        throw new UnsupportedOperationException();
    }

    protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
        this.engineInitSign(var1, null);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom var2) throws InvalidKeyException {
        if (!(privateKey instanceof SecurityKeyPrivateKey)) {
            throw new InvalidKeyException("PrivateKey is not a SecurityKeyPrivateKey");
        }
        this.securityKeyPrivateKey = (SecurityKeyPrivateKey) privateKey;

        String keyAlgorithm = privateKey.getAlgorithm();
        boolean isEccAlgo = "EC".equals(keyAlgorithm) && "ECDSA".equals(algorithmName);
        boolean isRsaAlgo = "RSA".equals(keyAlgorithm) && "RSA".equals(algorithmName);
        if (!isEccAlgo && !isRsaAlgo) {
            throw new InvalidKeyException("Expected algorithm '" +
                    algorithmName + "' for PrivateKey, found '" + keyAlgorithm + "'");
        }

        this.resetDigest();
    }

    private void resetDigest() {
        if (!this.digestReset) {
            if (this.md != null) {
                this.md.reset();
            }
            if (this.rawData != null) {
                this.rawData.reset();
            }
            this.digestReset = true;
        }
    }

    private byte[] getDigestValue() {
        this.digestReset = true;
        if (this.digestName != null) {
            return this.md.digest();
        } else {
            return this.rawData.toByteArray();
        }
    }

    protected void engineUpdate(byte var1) {
        if (this.md != null) {
            this.md.update(var1);
        }
        if (this.rawData != null) {
            this.rawData.write(var1);
        }
        this.digestReset = false;
    }

    protected void engineUpdate(byte[] var1, int var2, int var3) {
        if (this.md != null) {
            this.md.update(var1, var2, var3);
        }
        if (this.rawData != null) {
            this.rawData.write(var1, var2, var3);
        }
        this.digestReset = false;
    }

    protected void engineUpdate(ByteBuffer input) {
        if (this.md != null) {
            this.md.update(input);
        }
        if (this.rawData != null) {
            writeByteBufferToOuputStream(input, this.rawData);
        }
        this.digestReset = false;
    }

    protected byte[] engineSign() throws SignatureException {
        try {
            byte[] digest = this.getDigestValue();
            return securityKeyPrivateKey.securityKeyAuthenticator.authenticatePresignedDigest(digest, digestName);
        } catch (IOException e) {
            throw new SignatureException(e);
        }
    }

    protected boolean engineVerify(byte[] var1) {
        throw new UnsupportedOperationException();
    }

    @Deprecated
    protected void engineSetParameter(String var1, Object var2) throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Deprecated
    protected Object engineGetParameter(String var1) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    private static void writeByteBufferToOuputStream(ByteBuffer input, ByteArrayOutputStream output) {
        if (!input.hasRemaining()) {
            return;
        }
        if (input.hasArray()) {
            byte[] b = input.array();
            int ofs = input.arrayOffset();
            int pos = input.position();
            int lim = input.limit();
            output.write(b, ofs + pos, lim - pos);
            input.position(lim);
        } else {
            int len = input.remaining();
            byte[] tempArray = new byte[128];
            while (len > 0) {
                int chunk = Math.min(len, tempArray.length);
                input.get(tempArray, 0, chunk);
                output.write(tempArray, 0, chunk);
                len -= chunk;
            }
        }
    }

    public static final class SHA512withRSA extends SecurityKeySignature {
        public SHA512withRSA() {
            super("RSA", "SHA-512");
        }
    }

    public static final class SHA384withRSA extends SecurityKeySignature {
        public SHA384withRSA() {
            super("RSA", "SHA-384");
        }
    }

    public static final class SHA256withRSA extends SecurityKeySignature {
        public SHA256withRSA() {
            super("RSA", "SHA-256");
        }
    }

    public static final class SHA224withRSA extends SecurityKeySignature {
        public SHA224withRSA() {
            super("RSA", "SHA-224");
        }
    }

    public static final class SHA1withRSA extends SecurityKeySignature {
        public SHA1withRSA() {
            super("RSA", "SHA-1");
        }
    }

    public static final class NONEwithECDSA extends SecurityKeySignature {
        public NONEwithECDSA() {
            super("ECDSA", null);
        }
    }

    public static final class SHA256withECDSA extends SecurityKeySignature {
        public SHA256withECDSA() {
            super("ECDSA", "SHA-256");
        }
    }

    public static final class SHA384withECDSA extends SecurityKeySignature {
        public SHA384withECDSA() {
            super("ECDSA", "SHA-384");
        }
    }

    public static final class SHA512withECDSA extends SecurityKeySignature {
        public SHA512withECDSA() {
            super("ECDSA", "SHA-512");
        }
    }
}