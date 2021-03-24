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
import androidx.annotation.RestrictTo.Scope;

import com.google.auto.value.AutoValue;


// OpenPGP Card Spec: Algorithm Attributes: RSA
@RestrictTo(Scope.LIBRARY_GROUP)
@AutoValue
public abstract class RsaKeyFormat extends KeyFormat {

    public static final int ALGORITHM_ID = PublicKeyAlgorithmTags.RSA_GENERAL;

    public abstract int modulusLength();

    public abstract int exponentLength();

    public abstract RsaImportFormat rsaImportFormat();

    public static RsaKeyFormat getInstance(int modulusLength, int exponentLength, RsaImportFormat from) {
        return new AutoValue_RsaKeyFormat(modulusLength, exponentLength, from);
    }

    public static RsaKeyFormat getInstanceDefault2048BitFormat() {
        return getInstance(2048, 4, RsaImportFormat.CRT_WITH_MODULUS);
    }

    public RsaKeyFormat withModulus(int modulus) {
        return RsaKeyFormat.getInstance(modulus, exponentLength(), rsaImportFormat());
    }

    public static KeyFormat getInstanceFromBytes(byte[] bytes) {
        if (bytes.length < 6) {
            throw new IllegalArgumentException("Bad length for RSA attributes");
        }
        int modulusLength = bytes[1] << 8 | bytes[2];
        int exponentLength = bytes[3] << 8 | bytes[4];
        RsaImportFormat importFormat = RsaImportFormat.from(bytes[5]);

        return getInstance(modulusLength, exponentLength, importFormat);
    }

    @Override
    public byte[] toBytes(KeyType slot) {
        int i = 0;
        byte[] attrs = new byte[6];
        attrs[i++] = (byte) ALGORITHM_ID;
        attrs[i++] = (byte) ((modulusLength() >> 8) & 0xff);
        attrs[i++] = (byte) (modulusLength() & 0xff);
        attrs[i++] = (byte) ((exponentLength() >> 8) & 0xff);
        attrs[i++] = (byte) (exponentLength() & 0xff);
        attrs[i] = rsaImportFormat().getImportFormat();

        return attrs;
    }

    @Override
    public KeyFormatParser getKeyFormatParser() {
        return new RsaKeyFormatParser();
    }

    public enum RsaImportFormat {
        STANDARD((byte) 0x00, false, false),
        STANDARD_WITH_MODULUS((byte) 0x01, false, true),
        CRT((byte) 0x02, true, false),
        CRT_WITH_MODULUS((byte) 0x03, true, true);

        private byte importFormat;
        private boolean includeModulus;
        private boolean includeCrt;

        RsaImportFormat(byte importFormat, boolean includeCrt, boolean includeModulus) {
            this.importFormat = importFormat;
            this.includeModulus = includeModulus;
            this.includeCrt = includeCrt;
        }

        public static RsaImportFormat from(byte importFormatByte) {
            for (RsaImportFormat format : values()) {
                if (format.importFormat == importFormatByte) {
                    return format;
                }
            }
            return null;
        }

        public byte getImportFormat() {
            return importFormat;
        }

        public boolean isIncludeModulus() {
            return includeModulus;
        }

        public boolean isIncludeCrt() {
            return includeCrt;
        }
    }
}
