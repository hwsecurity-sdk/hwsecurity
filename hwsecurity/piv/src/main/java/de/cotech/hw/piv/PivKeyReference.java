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

package de.cotech.hw.piv;


public enum PivKeyReference {
    SECURE_MESSAGING (0X04, null),
    AUTHENTICATION (0X9A, "5FC105"),
    CARD_APPLICATION_ADMINISTRATION (0X9B, null),
    DIGITAL_SIGNATURE (0X9C, "5FC10A"),
    KEY_MANAGEMENT (0X9D, "5FC10B"),
    CARD_AUTHENTICATION (0X9E, "5FC101"),
    RETIRED_KEY_MANAGEMENT_01 (0x82, "5FC10D"),
    RETIRED_KEY_MANAGEMENT_02 (0x83, "5FC10E"),
    RETIRED_KEY_MANAGEMENT_03 (0x84, "5FC10F"),
    RETIRED_KEY_MANAGEMENT_04 (0x85, "5FC100"),
    RETIRED_KEY_MANAGEMENT_05 (0x86, "5FC111"),
    RETIRED_KEY_MANAGEMENT_06 (0x87, "5FC112"),
    RETIRED_KEY_MANAGEMENT_07 (0x88, "5FC113"),
    RETIRED_KEY_MANAGEMENT_08 (0x89, "5FC114"),
    RETIRED_KEY_MANAGEMENT_09 (0x8A, "5FC115"),
    RETIRED_KEY_MANAGEMENT_10 (0x8B, "5FC116"),
    RETIRED_KEY_MANAGEMENT_11 (0x8C, "5FC117"),
    RETIRED_KEY_MANAGEMENT_12 (0x8D, "5FC118"),
    RETIRED_KEY_MANAGEMENT_13 (0x8E, "5FC119"),
    RETIRED_KEY_MANAGEMENT_14 (0x8F, "5FC11A"),
    RETIRED_KEY_MANAGEMENT_15 (0x90, "5FC11B"),
    RETIRED_KEY_MANAGEMENT_16 (0x91, "5FC11C"),
    RETIRED_KEY_MANAGEMENT_17 (0x92, "5FC11D"),
    RETIRED_KEY_MANAGEMENT_18 (0x93, "5FC11E"),
    RETIRED_KEY_MANAGEMENT_19 (0x94, "5FC11F"),
    RETIRED_KEY_MANAGEMENT_20 (0x95, "5FC120");

    public final int referenceId;
    public final String dataObject;

    PivKeyReference(int referenceId, String dataObject) {
        this.referenceId = referenceId;
        this.dataObject = dataObject;
    }
}
