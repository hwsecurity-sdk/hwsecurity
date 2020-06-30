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

package de.cotech.hw.openpgp;


import android.os.Parcelable;

import com.google.auto.value.AutoValue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import de.cotech.hw.util.Hex;


/**
 * This class holds configuration options for OpenPgpSecurityKeyConnectionMode.
 */
@AutoValue
public abstract class OpenPgpSecurityKeyConnectionModeConfig implements Parcelable {

    private static final byte[] AID_SELECT_FILE_OPENPGP = Hex.decodeHexOrFail("D27600012401");

    public abstract List<byte[]> getOpenPgpAidPrefixes();

    static OpenPgpSecurityKeyConnectionModeConfig getDefaultConfig() {
        return new Builder()
                .addDefaultOpenPgpAidPrefixes()
                .build();
    }

    /**
     *  Builder for SecurityKeyManagerConfig.
     */
    @SuppressWarnings({ "unused" })
    public static class Builder {
        private ArrayList<byte[]> openPgpAidPrefixes = new ArrayList<>();

        /**
         * This adds the default OpenPGP-Card AID prefix to the list of accepted prefixes.
         *
         * Note that this prefix will be used by default if no explicit AID prefixes are added, so calling this method
         * is only useful if other prefixes have been added with {@link #addOpenPgpAidPrefix(String)}.
         */
        public Builder addDefaultOpenPgpAidPrefixes() {
            openPgpAidPrefixes.add(AID_SELECT_FILE_OPENPGP);
            return this;
        }

        /**
         * This adds an AID prefix to the list of accepted prefixes for the OpenPGP connection mode.
         *
         * Note that once an explicit prefix is added, the default prefix will no longer be included automatically.
         * To add the default back, use {@link #addDefaultOpenPgpAidPrefixes()}.
         *
         * @throws IllegalArgumentException if hexStringAidPrefix does not contain a valid hex-encoded byte sequence
         */
        public Builder addOpenPgpAidPrefix(String hexStringAidPrefix) {
            byte[] aidPrefix = Hex.decodeHexOrFail(hexStringAidPrefix);
            openPgpAidPrefixes.add(aidPrefix);
            return this;
        }

        /** This adds an AID prefix to the list of accepted prefixes. */
        public Builder addOpenPgpAidPrefix(byte[] aidPrefix) {
            aidPrefix = Arrays.copyOf(aidPrefix, aidPrefix.length);
            openPgpAidPrefixes.add(aidPrefix);
            return this;
        }

        /**
         * Constructs a SecurityKeyManagerConfig from the Builder.
         */
        public OpenPgpSecurityKeyConnectionModeConfig build() {
            if (openPgpAidPrefixes.isEmpty()) {
                addDefaultOpenPgpAidPrefixes();
            }
            return new AutoValue_OpenPgpSecurityKeyConnectionModeConfig(
                    Collections.unmodifiableList(openPgpAidPrefixes)
            );
        }
    }
}
