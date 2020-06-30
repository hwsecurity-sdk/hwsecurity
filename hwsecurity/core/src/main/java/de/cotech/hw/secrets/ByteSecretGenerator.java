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

package de.cotech.hw.secrets;


import androidx.annotation.NonNull;

import java.security.SecureRandom;


/**
 * A generator for {@link ByteSecret} instances.
 */
public class ByteSecretGenerator {
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    public static ByteSecretGenerator getInstance() {
        return new ByteSecretGenerator();
    }

    private SecureRandom random = new SecureRandom();

    private ByteSecretGenerator() {
    }

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
     * Creates a random alphanumeric ByteSecret of the given length.
     * <p>
     * The contained entropy will be about 6 bits to the power of numChars.
     */
    @NonNull
    public ByteSecret createRandomAlphaNumeric(int numChars) {
        char[] secret = new char[numChars];
        for (int i = 0; i < numChars; i++) {
            secret[i] = ALPHABET.charAt(random.nextInt(ALPHABET.length()));
        }
        return ByteSecret.fromCharArrayAsUtf8TakeOwnership(secret);
    }

    /**
     * Creates a random numeric ByteSecret of the given length.
     * <p>
     * The contained entropy will be about 3.3 bits to the power of numChars.
     */
    @NonNull
    public ByteSecret createRandomNumeric(int numChars) {
        char[] secret = new char[numChars];
        for (int i = 0; i < numChars; i++) {
            secret[i] = Character.forDigit(random.nextInt(10), 10);
        }
        return ByteSecret.fromCharArrayAsUtf8TakeOwnership(secret);
    }

}
