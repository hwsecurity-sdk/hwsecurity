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

package de.cotech.hw.openpgp.internal.openpgp;

import androidx.annotation.RestrictTo;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.util.Arrays;

// References:
// [0] RFC 4880 `OpenPGP Message Format`
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class KdfCalculator {
    public static class KdfCalculatorArguments {
        public KdfParameters.HashType digestAlgorithm;
        public byte[] salt;
        public int iterations;
    }

    public static byte[] calculateKdf(KdfCalculatorArguments kdfCalculatorArguments, byte[] pin) {
        Digest digester;
        switch (kdfCalculatorArguments.digestAlgorithm) {
            case SHA256:
                digester = new SHA256Digest();
                break;
            case SHA512:
                digester = new SHA512Digest();
                break;
            default:
                throw new RuntimeException("Unknown hash algorithm!");
        }
        byte[] salt = kdfCalculatorArguments.salt;
        int iterations = kdfCalculatorArguments.iterations;

        // prepare input to hash function
        byte[] data = new byte[salt.length + pin.length];
        System.arraycopy(salt, 0, data, 0, salt.length);
        System.arraycopy(pin, 0, data, salt.length, pin.length);

        // hash data repeatedly
        // the iteration count is actually the number of octets to be hashed
        // see 3.7.1.2 of [0]
        int q = iterations / data.length;
        int r = iterations % data.length;
        for (int i = 0; i < q; i++) {
            digester.update(data, 0, data.length);
        }
        digester.update(data, 0, r);

        byte[] digest = new byte[digester.getDigestSize()];
        digester.doFinal(digest, 0);

        // delete secrets from memory
        Arrays.fill(data, (byte) 0);

        return digest;
    }
}