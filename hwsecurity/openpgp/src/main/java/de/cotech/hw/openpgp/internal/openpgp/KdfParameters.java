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

import com.google.auto.value.AutoValue;

import java.io.IOException;
import java.nio.ByteBuffer;

import de.cotech.hw.internal.iso7816.Iso7816TLV;

@SuppressWarnings("unused") // just expose all included data
@AutoValue
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public abstract class KdfParameters {

    public enum HashType {
        SHA256, SHA512
    }

    public enum PasswordType {
        PW1, PW2, PW3
    }

    public abstract HashType getDigestAlgorithm();

    public abstract int getIterations();

    @SuppressWarnings("mutable")
    public abstract byte[] getSaltPw1();

    @SuppressWarnings("mutable")
    public abstract byte[] getSaltPw2();

    @SuppressWarnings("mutable")
    public abstract byte[] getSaltPw3();

    @SuppressWarnings("mutable")
    public abstract byte[] getHashUser();

    @SuppressWarnings("mutable")
    public abstract byte[] getHashAdmin();

    public abstract boolean isHasUsesKdf();


    public static KdfParameters fromKdfDo(byte[] kdfDo) throws IOException {
        // parse elements of KDF-DO
        Iso7816TLV[] tlvs = Iso7816TLV.readList(kdfDo, false);
        return new AutoValue_KdfParameters.Builder().parseKdfTLVs(tlvs).build();
    }

    public KdfCalculator.KdfCalculatorArguments forType(PasswordType passwordType) {
        byte[] salt = null;
        // select salt based on the specified password type
        switch (passwordType) {
            case PW1:
                salt = getSaltPw1();
                break;
            case PW2:
                salt = getSaltPw2();
                break;
            case PW3:
                salt = getSaltPw3();
                break;
        }
        KdfCalculator.KdfCalculatorArguments arguments = new KdfCalculator.KdfCalculatorArguments();
        arguments.digestAlgorithm = getDigestAlgorithm();
        arguments.salt = salt;
        arguments.iterations = getIterations();
        return arguments;
    }

    @AutoValue.Builder
    abstract static class Builder {
        abstract Builder digestAlgorithm(HashType digestAlgorithm);

        abstract Builder iterations(int iterations);

        abstract Builder saltPw1(byte[] saltPw1);

        abstract Builder saltPw2(byte[] saltPw2);

        abstract Builder saltPw3(byte[] saltPw3);

        abstract Builder hashUser(byte[] hashUser);

        abstract Builder hashAdmin(byte[] hashAdmin);

        abstract Builder hasUsesKdf(boolean hasUsesKdf);

        abstract KdfParameters build();

        public Builder() {
            hasUsesKdf(false);
            digestAlgorithm(HashType.SHA256);
            iterations(0);
            saltPw1(new byte[0]);
            saltPw2(new byte[0]);
            saltPw3(new byte[0]);
            hashUser(new byte[0]);
            hashAdmin(new byte[0]);
        }

        Builder parseKdfTLVs(Iso7816TLV[] tlvs) throws IOException {
            for (Iso7816TLV tlv : tlvs) {
                switch (tlv.mT) {
                    case 0x81:
                        switch (tlv.mV[0]) {
                            case (byte) 0x00:
                                // no KDF, plain password
                                hasUsesKdf(false);
                                break;
                            case (byte) 0x03:
                                // using KDF
                                hasUsesKdf(true);
                                break;
                            default:
                                throw new IOException("Unknown KDF algorithm!");
                        }
                        break;
                    case 0x82:
                        // hash algorithm
                        switch (tlv.mV[0]) {
                            case (byte) 0x08: // SHA256
                                digestAlgorithm(HashType.SHA256);
                                break;
                            case (byte) 0x0a: // SHA512
                                digestAlgorithm(HashType.SHA512);
                                break;
                            default:
                                throw new IOException("Unknown hash algorithm!");
                        }
                        break;
                    case 0x83:
                        // iteration count
                        ByteBuffer buf = ByteBuffer.wrap(tlv.mV);
                        iterations(buf.getInt());
                        break;
                    case 0x84:
                        saltPw1(tlv.mV);
                        break;
                    case 0x85:
                        saltPw2(tlv.mV);
                        break;
                    case 0x86:
                        saltPw3(tlv.mV);
                        break;
                    case 0x87:
                        hashUser(tlv.mV);
                        break;
                    case 0x88:
                        hashAdmin(tlv.mV);
                        break;
                }
            }
            return this;
        }
    }
}