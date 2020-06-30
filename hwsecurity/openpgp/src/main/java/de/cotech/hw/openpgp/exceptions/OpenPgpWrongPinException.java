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

package de.cotech.hw.openpgp.exceptions;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.exceptions.SecurityStatusNotSatisfiedException;

public class OpenPgpWrongPinException extends SecurityStatusNotSatisfiedException {
    public static final int SW_WRONG_PIN = SW_SECURITY_STATUS_NOT_SATISFIED;

    // older YubiKey NEO returns 63C2 or 63C1 (2 or 1 retries), reproduce with YubiKey NEO, SN 2624165
    public static final int SW_WRONG_PIN_YKNEO_1 = 0x63C1;
    public static final int SW_WRONG_PIN_YKNEO_2 = 0x63C2;

    private int pinRetriesLeft;
    private int pukRetriesLeft;

    @RestrictTo(Scope.LIBRARY_GROUP)
    public OpenPgpWrongPinException(int pinRetriesLeft, int pukRetriesLeft) {
        super("Security Key returned error: wrong PIN/PUK (or: command not allowed / secure messaging incorrect)");
        this.pinRetriesLeft = pinRetriesLeft;
        this.pukRetriesLeft = pukRetriesLeft;
    }

    public int getPinRetriesLeft() {
        return pinRetriesLeft;
    }

    public int getPukRetriesLeft() {
        return pukRetriesLeft;
    }
}
