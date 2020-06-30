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

package de.cotech.hw.secrets;


/**
 * A provider of security key PINs.
 * <p>
 * Security keys are locked with a PIN, which authenticates all secret key operations.
 * An instance of this interface is required as a parameter for all such operations.
 *
 * @see StaticPinProvider
 */
public interface PinProvider {
    /**
     * Returns a PIN for the security key identified by the given AID.
     *
     * The requirements for this PIN depend on the security key, but typically can be at least any sequence
     * of six or more alphanumeric characters.
     */
    ByteSecret getPin(byte[] securityKeyAid);

    /**
     * Returns a PUK for the security key identified by the given AID.
     *
     * The requirements for this PUK depend on the security key, but typically can be at least any sequence
     * of eight or more alphanumeric characters.
     */
    ByteSecret getPuk(byte[] securityKeyAid);
}
