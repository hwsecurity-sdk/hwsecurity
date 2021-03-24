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


@RestrictTo(Scope.LIBRARY_GROUP)
public enum KeyType {
    SIGN(0xB6, 0xCE, 0xC7, 0xC1),
    ENCRYPT(0xB8, 0xCF, 0xC8, 0xC2),
    AUTH(0xA4, 0xD0, 0xC9, 0xC3);

    private final int slot;
    private final int timestampObjectId;
    private final int fingerprintObjectId;
    private final int algoAttributeSlot;

    KeyType(int slot, int timestampObjectId, int fingerprintObjectId, int algoAttributeSlot) {
        this.slot = slot;
        this.timestampObjectId = timestampObjectId;
        this.fingerprintObjectId = fingerprintObjectId;
        this.algoAttributeSlot = algoAttributeSlot;
    }

    public int getSlot() {
        return slot;
    }

    public int getTimestampObjectId() {
        return timestampObjectId;
    }

    public int getFingerprintObjectId() {
        return fingerprintObjectId;
    }

    public int getAlgoAttributeSlot() {
        return algoAttributeSlot;
    }
}
