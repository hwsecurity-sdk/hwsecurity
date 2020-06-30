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

    @Override
    public byte[] toBytes(KeyType slot) {
        int i = 0;
        byte[] attrs = new byte[6];
        attrs[i++] = (byte) 0x01;
        attrs[i++] = (byte) ((mModulusLength >> 8) & 0xff);
        attrs[i++] = (byte) (mModulusLength & 0xff);
        attrs[i++] = (byte) ((mExponentLength >> 8) & 0xff);
        attrs[i++] = (byte) (mExponentLength & 0xff);
        attrs[i] = mRSAAlgorithmFormat.getValue();

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
        STANDARD((byte) 0, false, false),
        STANDARD_WITH_MODULUS((byte) 1, false, true),
        CRT((byte) 2, true, false),
        CRT_WITH_MODULUS((byte) 3, true, true);

        private byte mValue;
        private boolean mIncludeModulus;
        private boolean mIncludeCrt;

        RSAAlgorithmFormat(byte value, boolean includeCrt, boolean includeModulus) {
            mValue = value;
            mIncludeModulus = includeModulus;
            mIncludeCrt = includeCrt;
        }

        public static RSAAlgorithmFormat from(byte b) {
            for (RSAAlgorithmFormat format : values()) {
                if (format.mValue == b) {
                    return format;
                }
            }
            return null;
        }

        public byte getValue() {
            return mValue;
        }

        public boolean isIncludeModulus() {
            return mIncludeModulus;
        }

        public boolean isIncludeCrt() {
            return mIncludeCrt;
        }
    }
}
