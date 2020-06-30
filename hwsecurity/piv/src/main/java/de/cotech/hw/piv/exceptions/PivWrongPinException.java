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

package de.cotech.hw.piv.exceptions;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import de.cotech.hw.exceptions.SecurityStatusNotSatisfiedException;

public class PivWrongPinException extends SecurityStatusNotSatisfiedException {
    public static final int SW_WRONG_PIN = 0x6300;

    public static final int SW_WRONG_PIN_RETRIES_BASE = 0x63C0;

    private int retriesLeft;

    @RestrictTo(Scope.LIBRARY_GROUP)
    public PivWrongPinException(int retriesLeft) {
        super("Security Key returned error: wrong PIN/PUK");
        this.retriesLeft = retriesLeft;
    }

    public int getRetriesLeft() {
        return retriesLeft;
    }

}
