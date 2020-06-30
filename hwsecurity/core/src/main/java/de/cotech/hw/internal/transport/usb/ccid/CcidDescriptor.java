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

package de.cotech.hw.internal.transport.usb.ccid;

import com.google.auto.value.AutoValue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.VisibleForTesting;
import de.cotech.hw.internal.transport.usb.UsbTransportException;
import de.cotech.hw.internal.transport.usb.ccid.tpdu.T0ShortApduProtocol;
import de.cotech.hw.internal.transport.usb.ccid.tpdu.T1ShortApduProtocol;
import de.cotech.hw.internal.transport.usb.ccid.tpdu.T1TpduProtocol;


@AutoValue
@RestrictTo(Scope.LIBRARY_GROUP)
abstract class CcidDescriptor {
    private static final int DESCRIPTOR_LENGTH = 0x36;
    private static final int DESCRIPTOR_TYPE = 0x21;

    // dwFeatures Masks
    private static final int FEATURE_AUTOMATIC_VOLTAGE = 0x00008;
    private static final int FEATURE_AUTOMATIC_PPS = 0x00080;

    private static final int FEATURE_EXCHANGE_LEVEL_TPDU = 0x10000;
    private static final int FEATURE_EXCHANGE_LEVEL_SHORT_APDU = 0x20000;
    private static final int FEATURE_EXCHAGE_LEVEL_EXTENDED_APDU = 0x40000;

    // bVoltageSupport Masks
    private static final byte VOLTAGE_5V = 1;
    private static final byte VOLTAGE_3V = 2;
    private static final byte VOLTAGE_1_8V = 4;

    private static final int SLOT_OFFSET = 4;
    private static final int FEATURES_OFFSET = 40;
    private static final short MASK_T0_PROTO = 1;
    private static final short MASK_T1_PROTO = 2;

    public abstract byte getMaxSlotIndex();
    public abstract byte getVoltageSupport();
    public abstract int getProtocols();
    public abstract int getFeatures();

    @VisibleForTesting
    static CcidDescriptor fromValues(byte maxSlotIndex, byte voltageSupport, int protocols, int features) {
        return new AutoValue_CcidDescriptor(maxSlotIndex, voltageSupport, protocols, features);
    }

    @NonNull
    static CcidDescriptor fromRawDescriptors(byte[] desc) throws UsbTransportException {
        int dwProtocols = 0, dwFeatures = 0;
        byte bMaxSlotIndex = 0, bVoltageSupport = 0;

        boolean hasCcidDescriptor = false;

        ByteBuffer byteBuffer = ByteBuffer.wrap(desc).order(ByteOrder.LITTLE_ENDIAN);

        while (byteBuffer.hasRemaining()) {
            byteBuffer.mark();
            byte len = byteBuffer.get(), type = byteBuffer.get();

            if (type == DESCRIPTOR_TYPE && len == DESCRIPTOR_LENGTH) {
                byteBuffer.reset();

                byteBuffer.position(byteBuffer.position() + SLOT_OFFSET);
                bMaxSlotIndex = byteBuffer.get();
                bVoltageSupport = byteBuffer.get();
                dwProtocols = byteBuffer.getInt();

                byteBuffer.reset();

                byteBuffer.position(byteBuffer.position() + FEATURES_OFFSET);
                dwFeatures = byteBuffer.getInt();
                hasCcidDescriptor = true;
                break;
            } else {
                byteBuffer.position(byteBuffer.position() + len - 2);
            }
        }

        if (!hasCcidDescriptor) {
            throw new UsbTransportException("CCID descriptor not found");
        }

        return new AutoValue_CcidDescriptor(bMaxSlotIndex, bVoltageSupport, dwProtocols, dwFeatures);
    }

    Voltage[] getVoltages() {
        ArrayList<Voltage> voltages = new ArrayList<>();

        if (hasFeature(FEATURE_AUTOMATIC_VOLTAGE)) {
            voltages.add(Voltage.AUTO);
        } else {
            for (Voltage v : Voltage.values()) {
                if ((v.mask & getVoltageSupport()) != 0) {
                    voltages.add(v);
                }
            }
        }

        return voltages.toArray(new Voltage[voltages.size()]);
    }

    CcidTransportProtocol getSuitableTransportProtocol() throws UsbTransportException {
        boolean hasT1Protocol = (getProtocols() & MASK_T1_PROTO) != 0;
        if (hasT1Protocol) {
            if (hasFeature(CcidDescriptor.FEATURE_EXCHANGE_LEVEL_TPDU)) {
                return new T1TpduProtocol();
            } else if (hasFeature(CcidDescriptor.FEATURE_EXCHANGE_LEVEL_SHORT_APDU) ||
                    hasFeature(CcidDescriptor.FEATURE_EXCHAGE_LEVEL_EXTENDED_APDU)) {
                return new T1ShortApduProtocol();
            } else {
                throw new UsbTransportException("Character level exchange is not supported for T=1");
            }
        }

        boolean hasT0Protocol = (getProtocols() & MASK_T0_PROTO) != 0;
        if (hasT0Protocol) {
            if (hasFeature(CcidDescriptor.FEATURE_EXCHANGE_LEVEL_SHORT_APDU)) {
                return new T0ShortApduProtocol();
            } else if (hasFeature(CcidDescriptor.FEATURE_EXCHANGE_LEVEL_TPDU)) {
                throw new UsbTransportException("TPDU level exchange is not supported for T=0");
            } else {
                throw new UsbTransportException("Character level exchange is not supported for T=0");
            }
        }

        throw new UsbTransportException("No suitable usb protocol supported");
    }

    boolean hasAutomaticPps() {
        return hasFeature(FEATURE_AUTOMATIC_PPS);
    }

    private boolean hasFeature(int feature) {
        return (getFeatures() & feature) != 0;
    }

    enum Voltage {
        AUTO(0, 0), _5V(1, VOLTAGE_5V), _3V(2, VOLTAGE_3V), _1_8V(3, VOLTAGE_1_8V);

        final byte mask;
        final byte powerOnValue;

        Voltage(int powerOnValue, int mask) {
            this.powerOnValue = (byte) powerOnValue;
            this.mask = (byte) mask;
        }
    }
}
