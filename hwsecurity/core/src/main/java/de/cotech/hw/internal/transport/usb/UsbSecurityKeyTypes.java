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

package de.cotech.hw.internal.transport.usb;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import android.annotation.SuppressLint;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.internal.transport.SecurityKeyInfo;
import de.cotech.hw.internal.transport.Version;


@RestrictTo(Scope.LIBRARY_GROUP)
public class UsbSecurityKeyTypes {

    // https://github.com/Yubico/yubikey-personalization/blob/master/ykcore/ykdef.h
    private static final int VENDOR_YUBICO = 4176;
    private static final int PRODUCT_YUBIKEY_NEO_OTP_CCID = 273;
    private static final int PRODUCT_YUBIKEY_NEO_CCID = 274;
    private static final int PRODUCT_YUBIKEY_NEO_U2F_CCID = 277;
    private static final int PRODUCT_YUBIKEY_NEO_OTP_U2F_CCID = 278;
    private static final int PRODUCT_YUBIKEY_4_5_CCID = 1028;
    private static final int PRODUCT_YUBIKEY_4_5_OTP_CCID = 1029;
    private static final int PRODUCT_YUBIKEY_4_5_FIDO_CCID = 1030;
    private static final int PRODUCT_YUBIKEY_4_5_OTP_FIDO_CCID = 1031;

    // https://www.nitrokey.com/de/documentation/installation#p:nitrokey-pro&os:linux
    private static final int VENDOR_NITROKEY = 8352;
    private static final int PRODUCT_NITROKEY_PRO = 16648;
    private static final int PRODUCT_NITROKEY_START = 16913;
    private static final int PRODUCT_NITROKEY_STORAGE = 16649;

    private static final int VENDOR_FSIJ = 9035;
    private static final int VENDOR_LEDGER = 11415;

    private static final int VENDOR_GEMALTO = 2278;
    private static final int PRODUCT_PROX_DU = 21763;

    // https://github.com/trustcrypto/Android-OnlyKey-U2F/blob/master/app/src/main/res/xml/device_filter.xml
    private static final int VENDOR_ONLYKEY1 = 5824;
    private static final int PRODUCT_ONLYKEY1 = 1158;
    private static final int VENDOR_ONLYKEY2 = 7504;
    private static final int PRODUCT_ONLYKEY2 = 24828;

    private static final int VENDOR_ACS = 0x72f;
    private static final int PRODUCT_ACR1252 = 0x223e;

    @Nullable
    public static SecurityKeyInfo.SecurityKeyType getSecurityKeyTypeFromUsbDeviceInfo(int vendorId, int productId, String serialNo) {
        switch (vendorId) {
            case VENDOR_YUBICO: {
                switch (productId) {
                    case PRODUCT_YUBIKEY_NEO_OTP_CCID:
                    case PRODUCT_YUBIKEY_NEO_CCID:
                    case PRODUCT_YUBIKEY_NEO_U2F_CCID:
                    case PRODUCT_YUBIKEY_NEO_OTP_U2F_CCID:
                        return SecurityKeyInfo.SecurityKeyType.YUBIKEY_NEO;
                    case PRODUCT_YUBIKEY_4_5_CCID:
                    case PRODUCT_YUBIKEY_4_5_OTP_CCID:
                    case PRODUCT_YUBIKEY_4_5_FIDO_CCID:
                    case PRODUCT_YUBIKEY_4_5_OTP_FIDO_CCID:
                        return SecurityKeyInfo.SecurityKeyType.YUBIKEY_4_5;
                }
                break;
            }
            case VENDOR_NITROKEY: {
                switch (productId) {
                    case PRODUCT_NITROKEY_PRO:
                        return SecurityKeyInfo.SecurityKeyType.NITROKEY_PRO;
                    case PRODUCT_NITROKEY_START:
                        Version gnukVersion = SecurityKeyInfo.parseGnukVersionString(serialNo);
                        boolean versionGreaterEquals125 = gnukVersion != null
                                && Version.create("1.2.5").compareTo(gnukVersion) <= 0;
                        return versionGreaterEquals125 ? SecurityKeyInfo.SecurityKeyType.NITROKEY_START_1_25_AND_NEWER : SecurityKeyInfo.SecurityKeyType.NITROKEY_START_OLD;
                    case PRODUCT_NITROKEY_STORAGE:
                        return SecurityKeyInfo.SecurityKeyType.NITROKEY_STORAGE;
                }
                break;
            }
            case VENDOR_FSIJ: {
                Version gnukVersion = SecurityKeyInfo.parseGnukVersionString(serialNo);
                boolean versionGreaterEquals125 = gnukVersion != null
                        && Version.create("1.2.5").compareTo(gnukVersion) <= 0;
                return versionGreaterEquals125 ? SecurityKeyInfo.SecurityKeyType.GNUK_1_25_AND_NEWER : SecurityKeyInfo.SecurityKeyType.GNUK_OLD;
            }
            case VENDOR_LEDGER: {
                return SecurityKeyInfo.SecurityKeyType.LEDGER_NANO_S;
            }
            case VENDOR_ONLYKEY1: {
                switch (productId) {
                    case PRODUCT_ONLYKEY1:
                        return SecurityKeyInfo.SecurityKeyType.ONLYKEY;
                }
            }
            case VENDOR_ONLYKEY2: {
                switch (productId) {
                    case PRODUCT_ONLYKEY2:
                        return SecurityKeyInfo.SecurityKeyType.ONLYKEY;
                }
            }
            case VENDOR_GEMALTO: {
                switch (productId) {
                    case PRODUCT_PROX_DU:
                        return SecurityKeyInfo.SecurityKeyType.GEMALTO_PROX_DU;
                }
            }
            case VENDOR_ACS: {
                switch (productId) {
                    case PRODUCT_ACR1252:
                        return SecurityKeyInfo.SecurityKeyType.GEMALTO_PROX_DU;
                }
            }
        }

        return null;
    }

    static boolean isTestedSecurityKey(int vendorId, int productId) {
        return UsbSecurityKeyTypes.getSecurityKeyTypeFromUsbDeviceInfo(vendorId, productId, null) != null;
    }

    private static final Map<SecurityKeyInfo.SecurityKeyType, String> SECURITY_KEY_NAMES = createTypeNameMap();

    private static Map<SecurityKeyInfo.SecurityKeyType, String> createTypeNameMap() {
        // NOTE: Only add Security Keys, do not add smartcard reader!
        @SuppressLint("UseSparseArrays") Map<SecurityKeyInfo.SecurityKeyType, String> result = new HashMap<>();
        result.put(SecurityKeyInfo.SecurityKeyType.YUBIKEY_NEO, "YubiKey NEO");
        result.put(SecurityKeyInfo.SecurityKeyType.YUBIKEY_4_5, "YubiKey");
        result.put(SecurityKeyInfo.SecurityKeyType.NITROKEY_PRO, "Nitrokey Pro");
        result.put(SecurityKeyInfo.SecurityKeyType.NITROKEY_STORAGE, "Nitrokey Storage");
        result.put(SecurityKeyInfo.SecurityKeyType.NITROKEY_START_OLD, "Nitrokey Start");
        result.put(SecurityKeyInfo.SecurityKeyType.NITROKEY_START_1_25_AND_NEWER, "Nitrokey Start");
        result.put(SecurityKeyInfo.SecurityKeyType.GNUK_OLD, "Gnuk");
        result.put(SecurityKeyInfo.SecurityKeyType.GNUK_1_25_AND_NEWER, "Gnuk");
        result.put(SecurityKeyInfo.SecurityKeyType.LEDGER_NANO_S, "Ledger Nano S");
        result.put(SecurityKeyInfo.SecurityKeyType.ONLYKEY, "OnlyKey");
        return Collections.unmodifiableMap(result);
    }

    public static String getSecurityKeyName(SecurityKeyInfo.SecurityKeyType securityKeyType) {
        return SECURITY_KEY_NAMES.get(securityKeyType);
    }

}
