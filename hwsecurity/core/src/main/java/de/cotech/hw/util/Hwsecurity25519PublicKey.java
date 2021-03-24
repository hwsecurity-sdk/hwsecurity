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

package de.cotech.hw.util;

import java.security.PublicKey;

/**
 * Wrapper class for Ed25519 and X25519 keys, since there are no PublicKey classes
 * in Android for Curve25519 keys.
 * <p>
 * Hwsecurity25519PublicKey can be converted to Bouncy Castle PublicKeys using
 * Bouncy25519KeyConverter from hwsecurity-openpgp artifact.
 */
public class Hwsecurity25519PublicKey implements PublicKey {
    private byte[] rawPublicKey;
    private String algorithm;

    /**
     * @param rawPublicKey bytes of the compressed point
     * @param algorithm    either "Ed25519" or "X25519"
     */
    public Hwsecurity25519PublicKey(byte[] rawPublicKey, String algorithm) {
        this.rawPublicKey = rawPublicKey;
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "hwsecurity";
    }

    @Override
    public byte[] getEncoded() {
        return rawPublicKey;
    }
}
