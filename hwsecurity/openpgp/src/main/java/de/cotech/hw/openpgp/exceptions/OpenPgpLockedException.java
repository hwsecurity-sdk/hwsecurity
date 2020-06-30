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
import de.cotech.hw.exceptions.AuthenticationMethodBlockedException;

public class OpenPgpLockedException extends AuthenticationMethodBlockedException {
    public static final int SW_OPENPGP_LOCKED = SW_AUTHENTICATION_METHOD_BLOCKED;

    // older YubiKey NEO returns 63C0 (0 retries), reproduce with YubiKey NEO, SN 2624165
    public static final int SW_OPENPGP_LOCKED_YKNEO = 0x63C0;

    @RestrictTo(Scope.LIBRARY_GROUP)
    public OpenPgpLockedException() {
        super("Security Key returned error: PIN/PUK locked, an incorrect PIN/PUK has been entered 3 times.");
    }
}
