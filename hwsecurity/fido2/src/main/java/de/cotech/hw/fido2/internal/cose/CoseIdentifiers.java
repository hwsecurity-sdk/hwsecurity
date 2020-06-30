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

package de.cotech.hw.fido2.internal.cose;


import de.cotech.hw.fido2.internal.cbor_java.model.NegativeInteger;
import de.cotech.hw.fido2.internal.cbor_java.model.Number;
import de.cotech.hw.fido2.internal.cbor_java.model.UnsignedInteger;


public class CoseIdentifiers {
    public static final Number KTY = new UnsignedInteger(1);
    public static final Number ALG = new UnsignedInteger(3);
    public static final Number CRV = new NegativeInteger(-1);
    public static final Number X = new NegativeInteger(-2);
    public static final Number Y = new NegativeInteger(-3);
    public static final Number KTY_EC2 = new UnsignedInteger(2);
    public static final Number CRV_P256 = new UnsignedInteger(1);

    public enum CoseAlg {
        ES256(-7), ECDH_ES_w_HKDF_256(-25);

        public final int label;
        public final Number cborLabel;

        public static CoseAlg fromIdentifier(int label) {
            switch (label) {
                case -7:
                    return ES256;
                default:
                    return null;
            }
        }

        CoseAlg(int label) {
            this.label = label;
            this.cborLabel = label < 0 ? new NegativeInteger(label) : new UnsignedInteger(label);
        }
    }
}