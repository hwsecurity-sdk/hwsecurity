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

package de.cotech.hw.openpgp.secrets;


import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.util.Arrays;

import de.cotech.hw.secrets.ByteSecret;


/**
 * A generator for {@link ByteSecret} instances.
 */
public class OpenPgpByteSecretGenerator {

    public static OpenPgpByteSecretGenerator getInstance() {
        return new OpenPgpByteSecretGenerator();
    }

    private OpenPgpByteSecretGenerator() {
    }

    /**
     * Derives a ByteSecret using SHA256, compatible to RFC 5869
     */
    @Deprecated
    public ByteSecret deriveWithSaltAndConsume(ByteSecret secret, String salt, int length) {
        byte[] secretBytes = null;
        try {
            secretBytes = secret.getByteCopyAndClear();

            SHA256Digest digest = new SHA256Digest();
            HKDFBytesGenerator kDF1BytesGenerator = new HKDFBytesGenerator(digest);

            kDF1BytesGenerator.init(new HKDFParameters(secretBytes, salt.getBytes(), null));

            byte[] derivedSecret = new byte[length];
            kDF1BytesGenerator.generateBytes(derivedSecret, 0, length);

            return ByteSecret.fromByteArrayAndClear(derivedSecret);
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

}
