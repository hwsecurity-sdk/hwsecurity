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


import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.WrongDataException;
import de.cotech.hw.exceptions.WrongRequestLengthException;

public class OpenPgpPinTooShortException extends SecurityKeyException {
    /*
     * Used in
     * - ykneo-openpgp >= 1.0.11
     * https://github.com/Yubico/ykneo-openpgp/commit/b49ce8241917e7c087a4dab7b2c755420ff4500f
     * - YubiKey 5C
     */
    public static final int SW_WRONG_DATA = WrongDataException.SW_WRONG_DATA;

    /*
     * Used in
     * - ykneo-openpgp < 1.0.10
     * - SmartPGP
     */
    public static final int SW_WRONG_REQUEST_LENGTH = WrongRequestLengthException.SW_WRONG_REQUEST_LENGTH;

    public OpenPgpPinTooShortException() {
        super("Security Key returned error: PIN too short.", 0);
    }

}
