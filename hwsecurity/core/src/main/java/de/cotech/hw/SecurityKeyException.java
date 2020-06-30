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

package de.cotech.hw;

import java.io.IOException;

import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;


/**
 * Base exception of the Hardware Security SDK.
 *
 * @see de.cotech.hw.exceptions
 */
@RestrictTo(Scope.LIBRARY_GROUP)
public class SecurityKeyException extends IOException {
    private short responseCode;
    private String shortErrorName;

    private SecurityKeyException(String detailMessage, String shortErrorName, short responseCode) {
        super(detailMessage);
        this.responseCode = responseCode;
        this.shortErrorName = shortErrorName;
    }

    public SecurityKeyException(String shortErrorName, int responseCode) {
        this("Security Key returned error " + shortErrorName + " (0x" + Integer.toHexString(responseCode) + ")",
                shortErrorName, (short) responseCode);
        if (responseCode > Short.MAX_VALUE || responseCode< Short.MIN_VALUE) {
            throw new IllegalArgumentException("Response code must fit in two bytes!");
        }
    }

    public SecurityKeyException(String detailMessage, String shortErrorName, int responseCode) {
        this(detailMessage, shortErrorName, (short) responseCode);
        if (responseCode > Short.MAX_VALUE || responseCode< Short.MIN_VALUE) {
            throw new IllegalArgumentException("Response code must fit in two bytes!");
        }
    }

    public String getShortErrorName() {
        return shortErrorName;
    }

    public short getResponseCode() {
        return responseCode;
    }

}