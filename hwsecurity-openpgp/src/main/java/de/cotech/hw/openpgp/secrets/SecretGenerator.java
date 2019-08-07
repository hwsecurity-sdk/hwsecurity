/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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

package de.cotech.hw.openpgp.secrets;


import java.security.SecureRandom;
import java.util.Arrays;

import androidx.annotation.NonNull;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.CharSecret;


/**
 * A generator for {@link ByteSecret} and {@link CharSecret} instances.
 */
public class SecretGenerator {
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    public static SecretGenerator getInstance() {
        return new SecretGenerator();
    }

    private SecureRandom random = new SecureRandom();

    private SecretGenerator() { }

    /**
     * Creates a random ByteSecret of the given length.
     * <p>
     * The contained entropy will be about 8 bits to the power of numBytes.
     */
    @NonNull
    public ByteSecret createRandom(int numBytes) {
        byte[] secret = new byte[numBytes];
        random.nextBytes(secret);
        return ByteSecret.fromByteArrayTakeOwnership(secret);
    }

    /**
     * Creates a random alphanumeric CharSecret of the given length.
     * <p>
     * The contained entropy will be about 6 bits to the power of numChars.
     */
    @NonNull
    public CharSecret createRandomAlphaNumeric(int numChars) {
        char[] secret = new char[numChars];
        for (int i = 0; i < numChars; i++) {
            secret[i] = ALPHABET.charAt(random.nextInt(ALPHABET.length()));
        }
        return CharSecret.fromCharArrayTakeOwnership(secret);
    }

    /**
     * Creates a random numeric CharSecret of the given length.
     * <p>
     * The contained entropy will be about 3.3 bits to the power of numChars.
     */
    @NonNull
    public CharSecret createRandomNumeric(int numChars) {
        char[] secret = new char[numChars];
        for (int i = 0; i < numChars; i++) {
            secret[i] = Character.forDigit(random.nextInt(10), 10);
        }
        return CharSecret.fromCharArrayTakeOwnership(secret);
    }

    /** Derives a ByteSecret using SHA256, compatible to RFC 5869 */
    public CharSecret deriveWithSaltAndConsume(ByteSecret secret, String salt, int length) {
        byte[] secretBytes = null;
        try {
            secretBytes = secret.getByteCopyAndClear();

            SHA256Digest digest = new SHA256Digest();
            HKDFBytesGenerator kDF1BytesGenerator = new HKDFBytesGenerator(digest);

            kDF1BytesGenerator.init(new HKDFParameters(secretBytes, salt.getBytes(), null));

            byte[] derivedSecret = new byte[length];
            kDF1BytesGenerator.generateBytes(derivedSecret, 0, length);

            char[] charSecret = byteSecretToCharSecretAndConsume(derivedSecret);
            return CharSecret.fromCharArrayTakeOwnership(charSecret);
        } finally {
            zeroArrayQuietly(secretBytes);
        }
    }

    private void zeroArrayQuietly(byte[] secretBytes) {
        if (secretBytes != null) {
            Arrays.fill(secretBytes, (byte) 0);
        }
    }

    private void zeroArrayQuietly(char[] secretChars) {
        if (secretChars != null) {
            Arrays.fill(secretChars, '\0');
        }
    }

    private char[] byteSecretToCharSecretAndConsume(byte[] secretBytes) {
        try {
            char[] result = new char[secretBytes.length];
            for (int i = 0; i < result.length; i++) {
                result[i] = (char) secretBytes[i];
            }
            return result;
        } finally {
            zeroArrayQuietly(secretBytes);
        }
    }

}
