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

package de.cotech.hw.internal.transport;


import android.os.Parcelable;

import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;

import com.google.auto.value.AutoValue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@AutoValue
@RestrictTo(Scope.LIBRARY_GROUP)
public abstract class SecurityKeyInfo implements Parcelable {
    private static final byte[] EMPTY_ARRAY = new byte[20];
    private static final Pattern GNUK_VERSION_PATTERN = Pattern.compile("FSIJ-(\\d\\.\\d\\.\\d)-.+");

    public abstract TransportType getTransportType();
    public abstract SecurityKeyType getSecurityKeyType();

    public abstract List<byte[]> getFingerprints();
    @Nullable
    @SuppressWarnings("mutable")
    public abstract byte[] getAid();
    @Nullable
    public abstract String getUserId();
    @Nullable
    public abstract String getUrl();
    public abstract int getVerifyRetries();
    public abstract int getVerifyAdminRetries();
    public abstract boolean hasLifeCycleManagement();

    public boolean isEmpty() {
        return getFingerprints().isEmpty();
    }

    public static SecurityKeyInfo create(TransportType transportType, SecurityKeyType securityKeyType, byte[][] fingerprints,
                                         byte[] aid, String userId, String url,
                                         int verifyRetries, int verifyAdminRetries,
                                         boolean hasLifeCycleSupport) {
        ArrayList<byte[]> fingerprintList = new ArrayList<>(fingerprints.length);
        for (byte[] fingerprint : fingerprints) {
            if (!Arrays.equals(EMPTY_ARRAY, fingerprint)) {
                fingerprintList.add(fingerprint);
            }
        }
        return new AutoValue_SecurityKeyInfo(
                transportType, securityKeyType, fingerprintList, aid, userId, url, verifyRetries, verifyAdminRetries, hasLifeCycleSupport);
    }

    public enum TransportType {
        NFC, USB_CCID, USB_CTAPHID
    }

    public enum SecurityKeyType {
        YUBIKEY_NEO, YUBIKEY_4_5, FIDESMO, NITROKEY_PRO, NITROKEY_STORAGE, NITROKEY_START_OLD,
        NITROKEY_START_1_25_AND_NEWER, GNUK_OLD, GNUK_1_25_AND_NEWER, LEDGER_NANO_S, GEMALTO_PROX_DU, ACS_ACR1252,
        ONLYKEY, UNKNOWN
    }

    public static final Set<SecurityKeyType> SUPPORTED_USB_SECURITY_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            SecurityKeyType.YUBIKEY_NEO,
            SecurityKeyType.YUBIKEY_4_5,
            SecurityKeyType.NITROKEY_PRO,
            SecurityKeyType.NITROKEY_STORAGE,
            SecurityKeyType.NITROKEY_START_OLD,
            SecurityKeyType.NITROKEY_START_1_25_AND_NEWER,
            SecurityKeyType.GNUK_OLD,
            SecurityKeyType.GNUK_1_25_AND_NEWER,
            SecurityKeyType.LEDGER_NANO_S,
            SecurityKeyType.GEMALTO_PROX_DU,
            SecurityKeyType.ACS_ACR1252
    )));

    private static final Set<SecurityKeyType> SUPPORTED_USB_SETUP = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            SecurityKeyType.YUBIKEY_NEO,
            SecurityKeyType.YUBIKEY_4_5,
            SecurityKeyType.NITROKEY_PRO,
            SecurityKeyType.NITROKEY_STORAGE,
            SecurityKeyType.NITROKEY_START_1_25_AND_NEWER,
            SecurityKeyType.GNUK_1_25_AND_NEWER
    )));

    public boolean isPutKeySupported() {
        boolean isKnownSupported = SUPPORTED_USB_SETUP.contains(getSecurityKeyType());
        boolean isNfcTransport = getTransportType() == TransportType.NFC;

        return isKnownSupported || isNfcTransport;
    }

    public boolean isResetSupported() {
        boolean isKnownSupported = SUPPORTED_USB_SETUP.contains(getSecurityKeyType());
        boolean isNfcTransport = getTransportType() == TransportType.NFC;
        boolean hasLifeCycleManagement = hasLifeCycleManagement();

        return (isKnownSupported || isNfcTransport) && hasLifeCycleManagement;
    }

    public static Version parseGnukVersionString(String serialNo) {
        if (serialNo == null) {
            return null;
        }

        Matcher matcher = GNUK_VERSION_PATTERN.matcher(serialNo);
        if (!matcher.matches()) {
            return null;
        }
        return Version.create(matcher.group(1));
    }

}
