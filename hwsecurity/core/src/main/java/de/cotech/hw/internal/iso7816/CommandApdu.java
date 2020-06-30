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

package de.cotech.hw.internal.iso7816;


import java.io.IOException;
import java.util.Arrays;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import com.google.auto.value.AutoValue;

import de.cotech.hw.util.Hex;


/**
 * A command APDU following the structure defined in ISO/IEC 7816-4.
 * It consists of a four byte header and a conditional body of variable length.
 */
@AutoValue
@RestrictTo(Scope.LIBRARY_GROUP)
public abstract class CommandApdu {
    public static final int MAX_APDU_NC_SHORT = 255;
    public static final int MAX_APDU_NC_EXTENDED = 65535;
    public static final int MAX_APDU_NE_SHORT = 256;
    public static final int MAX_APDU_NE_EXTENDED = 65536;

    /**
     * Default Ne (expected response data length) is 0.
     * This means that the response should return NO DATA
     * (responses will be the result code only, such as "0x9000").
     * <p>
     * Javacards will probably still return data as they don't comply with ISO/IEC 7816-4 in this case.
     * <p>
     * Result: Command's Le value is absent
     */
    public static final int DEFAULT_APDU_NE_ZERO = 0;


    public abstract int getCLA();
    public abstract int getINS();
    public abstract int getP1();
    public abstract int getP2();
    @SuppressWarnings("mutable")
    public abstract byte[] getData();
    public abstract int getNe();

    @Nullable
    abstract CommandApduDescriber getDescriber();

    public int getNc() {
        byte[] data = getData();
        return data != null ? data.length : 0;
    }

    public static CommandApdu create(CommandApduDescriber describer, byte[] apdu, int apduOffset, int apduLength)
            throws IOException {
        return fromBytes(Arrays.copyOfRange(apdu, apduOffset, apduOffset + apduLength));
    }

    public static CommandApdu create(int cla, int ins, int p1, int p2) {
        return create(cla, ins, p1, p2, null, 0, 0, DEFAULT_APDU_NE_ZERO, null);
    }

    public static CommandApdu create(int cla, int ins, int p1, int p2, int ne) {
        return create(cla, ins, p1, p2, null, 0, 0, ne, null);
    }

    public static CommandApdu create(int cla, int ins, int p1, int p2, byte[] data) {
        return create(cla, ins, p1, p2, data, 0, data.length, DEFAULT_APDU_NE_ZERO, null);
    }

    public static CommandApdu create(int cla, int ins, int p1, int p2, byte[] data, int dataOffset, int dataLength) {
        return create(cla, ins, p1, p2, data, dataOffset, dataLength, DEFAULT_APDU_NE_ZERO, null);
    }

    public static CommandApdu create(int cla, int ins, int p1, int p2, byte[] data, int ne, CommandApduDescriber describer) {
        return create(cla, ins, p1, p2, data, 0, data.length, ne, describer);
    }

    public static CommandApdu create(int cla, int ins, int p1, int p2, byte[] data, int ne) {
        return create(cla, ins, p1, p2, data, 0, data.length, ne, null);
    }

    public static CommandApdu create(
            int cla, int ins, int p1, int p2, byte[] data, int dataOffset, int dataLength, int ne, CommandApduDescriber describer) {
        if (ne < DEFAULT_APDU_NE_ZERO) {
            throw new IllegalArgumentException("ne must not be negative");
        }
        if (ne > MAX_APDU_NE_EXTENDED) {
            throw new IllegalArgumentException("ne is too large");
        }
        if (data != null) {
            data = Arrays.copyOfRange(data, dataOffset, dataOffset + dataLength);
        } else {
            data = new byte[0];
        }

        return new AutoValue_CommandApdu(cla, ins, p1, p2, data, ne, describer);
    }

    public CommandApdu withNe(int ne) {
        return create(getCLA(), getINS(), getP1(), getP2(), getData(), ne, getDescriber());
    }

    /**
     * Set Ne (expected response data length) so that the response returns all bytes
     * within the limit of 256.
     * <p>
     * Only sets Ne if default of 0 has no changed.
     * <p>
     * Result: Command's Le value is set to 0x00
     */
    public CommandApdu withShortApduNe() {
        if (getNe() == DEFAULT_APDU_NE_ZERO) {
            return withNe(MAX_APDU_NE_SHORT);
        } else {
            return this;
        }
    }

    /**
     * Set Ne (expected response data length) so that the response returns all bytes
     * within the limit of 65536.
     * <p>
     * Only sets Ne if default of 0 has no changed.
     * <p>
     * Result: Command's Le value is set to 0x0000
     */
    public CommandApdu withExtendedApduNe() {
        if (getNe() == DEFAULT_APDU_NE_ZERO) {
            return withNe(MAX_APDU_NE_EXTENDED);
        } else {
            return this;
        }
    }

    /**
     * Override Ne to 65536
     */
    public CommandApdu forceExtendedApduNe() {
        return withNe(MAX_APDU_NE_EXTENDED);
    }

    public CommandApdu withDescriber(CommandApduDescriber describer) {
        return create(getCLA(), getINS(), getP1(), getP2(), getData(), getNe(), describer);
    }

    public static CommandApdu fromBytes(byte[] apdu, int offset, int length) throws IOException {
        return fromBytes(Arrays.copyOfRange(apdu, offset, offset + length));
    }

    /**
     * Command APDU encoding options:
     * <p>
     * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
     * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
     * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
     * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
     * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
     * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
     * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len =10..65544
     * <p>
     * LE, LE1, LE2 may be 0x00.
     * LC must not be 0x00 and LC1|LC2 must not be 0x00|0x00
     * <p>
     * see https://docs.oracle.com/javacard/3.0.5/prognotes/extended-apdu-nominal-cases.htm
     */
    public static CommandApdu fromBytes(byte[] apdu) throws IOException {
        if (apdu.length < 4) {
            throw new IOException("apdu must be at least 4 bytes long");
        }

        int cla = apdu[0] & 0xff;
        int ins = apdu[1] & 0xff;
        int p1 = apdu[2] & 0xff;
        int p2 = apdu[3] & 0xff;
        final Integer dataOffset;
        final Integer dataLength;
        final int ne;

        if (apdu.length == 4) {
            // case 1
            dataOffset = null;
            dataLength = null;
            ne = 0;
        } else if (apdu.length == 5) {
            // case 2s
            dataOffset = null;
            dataLength = null;
            ne = (apdu[4] == 0) ? 256 : (apdu[4] & 0xff);
        } else if (apdu[4] != 0) {
            dataOffset = 5;
            dataLength = apdu[4] & 0xff;

            if (apdu.length == 4 + 1 + dataLength) {
                // case 3s
                ne = 0;
            } else {
                // case 4s
                int l2 = apdu[apdu.length - 1] & 0xff;
                ne = (l2 == 0) ? 256 : l2;
            }
        } else {
            int l2 = ((apdu[5] & 0xff) << 8) | (apdu[6] & 0xff);
            if (apdu.length == 7) {
                // case 2e
                dataOffset = null;
                dataLength = null;
                ne = (l2 == 0) ? 65536 : l2;
            } else {
                dataOffset = 7;
                dataLength = l2;

                if (apdu.length == 4 + 3 + l2) {
                    // case 3e
                    ne = 0;
                } else {
                    // case 4e
                    int leOfs = apdu.length - 2;
                    int le = ((apdu[leOfs] & 0xff) << 8) | (apdu[leOfs + 1] & 0xff);
                    ne = (le == 0) ? 65536 : le;
                }
            }
        }

        byte[] data;
        if (dataOffset != null) {
            data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLength);
        } else {
            data = new byte[0];
        }

        return new AutoValue_CommandApdu(cla, ins, p1, p2, data, ne, null);
    }

    public byte[] toBytes() {
        final byte[] apdu;

        byte[] data = getData();
        int ne = getNe();
        if (data.length == 0) {
            if (ne == 0) {
                // case 1
                apdu = new byte[4];
            } else {
                // case 2s or 2e
                if (ne <= 256) {
                    // case 2s
                    apdu = new byte[5];
                    apdu[4] = (ne != 256) ? (byte) ne : 0;
                } else {
                    // case 2e
                    apdu = new byte[7];
                    if (ne != 65536) {
                        apdu[5] = (byte) (ne >> 8);
                        apdu[6] = (byte) ne;
                    } else {
                        apdu[5] = 0;
                        apdu[6] = 0;
                    }
                }
            }
        } else {
            if (ne == 0) {
                // case 3s or 3e
                if (data.length <= 255) {
                    // case 3s
                    apdu = new byte[4 + 1 + data.length];
                    apdu[4] = (byte) data.length;
                    System.arraycopy(data, 0, apdu, 5, data.length);
                } else {
                    // case 3e
                    apdu = new byte[4 + 3 + data.length];
                    apdu[4] = 0;
                    apdu[5] = (byte) (data.length >> 8);
                    apdu[6] = (byte) data.length;
                    System.arraycopy(data, 0, apdu, 7, data.length);
                }
            } else {
                if (data.length <= 255 && ne <= 256) {
                    // case 4s
                    apdu = new byte[4 + 2 + data.length];
                    apdu[4] = (byte) data.length;
                    System.arraycopy(data, 0, apdu, 5, data.length);
                    apdu[apdu.length - 1] = (ne != 256) ? (byte) ne : 0;
                } else {
                    // case 4e
                    apdu = new byte[4 + 5 + data.length];
                    apdu[4] = 0;
                    apdu[5] = (byte) (data.length >> 8);
                    apdu[6] = (byte) data.length;
                    System.arraycopy(data, 0, apdu, 7, data.length);
                    if (ne != 65536) {
                        apdu[apdu.length - 2] = (byte) (ne >> 8);
                        apdu[apdu.length - 1] = (byte) ne;
                    } else {
                        apdu[apdu.length - 2] = 0;
                        apdu[apdu.length - 1] = 0;
                    }
                }
            }
        }

        apdu[0] = (byte) getCLA();
        apdu[1] = (byte) getINS();
        apdu[2] = (byte) getP1();
        apdu[3] = (byte) getP2();

        return apdu;
    }

    @Override
    final public String toString() {
        CommandApduDescriber describer = getDescriber();
        if (describer != null) {
            return describer.describe(this);
        } else {
            return Hex.encodeHexString(toBytes());
        }
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(toBytes());
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof CommandApdu) {
            return Arrays.equals(toBytes(), ((CommandApdu) other).toBytes());
        }
        return false;
    }
}
