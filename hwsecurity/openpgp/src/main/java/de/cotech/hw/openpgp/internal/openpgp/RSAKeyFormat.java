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

package de.cotech.hw.openpgp.internal.openpgp;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;


// 4.3.3.6 Algorithm Attributes
@RestrictTo(Scope.LIBRARY_GROUP)
public class RSAKeyFormat extends KeyFormat {
    private int mModulusLength;
    private int mExponentLength;
    private RSAAlgorithmFormat mRSAAlgorithmFormat;

    public static RSAKeyFormat getDefault2048BitFormat() {
        return new RSAKeyFormat(2048, 4, RSAAlgorithmFormat.CRT_WITH_MODULUS);
    }

    RSAKeyFormat(int modulusLength,
                 int exponentLength,
                 RSAAlgorithmFormat rsaAlgorithmFormat) {
        super(KeyFormatType.RSAKeyFormatType);
        mModulusLength = modulusLength;
        mExponentLength = exponentLength;
        mRSAAlgorithmFormat = rsaAlgorithmFormat;
    }

    public int getModulusLength() {
        return mModulusLength;
    }

    public int getExponentLength() {
        return mExponentLength;
    }

    public RSAAlgorithmFormat getAlgorithmFormat() {
        return mRSAAlgorithmFormat;
    }

    public RSAKeyFormat withModulus(int modulus) {
        return new RSAKeyFormat(modulus, mExponentLength, mRSAAlgorithmFormat);
    }

    public static KeyFormat fromBytes(byte[] bytes) {
        if (bytes.length < 6) {
            throw new IllegalArgumentException("Bad length for RSA attributes");
        }
        return new RSAKeyFormat(bytes[1] << 8 | bytes[2],
                bytes[3] << 8 | bytes[4],
                RSAKeyFormat.RSAAlgorithmFormat.from(bytes[5]));
    }

    @Override
    public byte[] toBytes(KeyType slot) {
        int i = 0;
        byte[] attrs = new byte[6];
        attrs[i++] = (byte) PublicKeyAlgorithmTags.RSA_GENERAL;
        attrs[i++] = (byte) ((mModulusLength >> 8) & 0xff);
        attrs[i++] = (byte) (mModulusLength & 0xff);
        attrs[i++] = (byte) ((mExponentLength >> 8) & 0xff);
        attrs[i++] = (byte) (mExponentLength & 0xff);
        attrs[i] = mRSAAlgorithmFormat.getImportFormat();

        return attrs;
    }

    @Override
    public KeyFormatParser getKeyFormatParser() {
        return new RSAKeyFormatParser();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        RSAKeyFormat that = (RSAKeyFormat) o;
        return mModulusLength == that.mModulusLength &&
                mExponentLength == that.mExponentLength &&
                mRSAAlgorithmFormat == that.mRSAAlgorithmFormat;
    }

    @Override
    public int hashCode() {
        int result = mModulusLength;
        result = 31 * result + mExponentLength;
        result = 31 * result + (mRSAAlgorithmFormat != null ? mRSAAlgorithmFormat.hashCode() : 0);
        return result;
    }

    public enum RSAAlgorithmFormat {
        STANDARD((byte) 0x00, false, false),
        STANDARD_WITH_MODULUS((byte) 0x01, false, true),
        CRT((byte) 0x02, true, false),
        CRT_WITH_MODULUS((byte) 0x03, true, true);

        private byte mImportFormat;
        private boolean mIncludeModulus;
        private boolean mIncludeCrt;

        RSAAlgorithmFormat(byte importFormat, boolean includeCrt, boolean includeModulus) {
            mImportFormat = importFormat;
            mIncludeModulus = includeModulus;
            mIncludeCrt = includeCrt;
        }

        public static RSAAlgorithmFormat from(byte importFormatByte) {
            for (RSAAlgorithmFormat format : values()) {
                if (format.mImportFormat == importFormatByte) {
                    return format;
                }
            }
            return null;
        }

        public byte getImportFormat() {
            return mImportFormat;
        }

        public boolean isIncludeModulus() {
            return mIncludeModulus;
        }

        public boolean isIncludeCrt() {
            return mIncludeCrt;
        }
    }
}
