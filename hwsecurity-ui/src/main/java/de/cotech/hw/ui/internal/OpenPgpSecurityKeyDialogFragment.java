/*
 * Copyright (C) 2018-2019 Confidential Technologies GmbH
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

package de.cotech.hw.ui.internal;

import android.os.Bundle;

import androidx.annotation.RestrictTo;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.openpgp.OpenPgpSecurityKey;
import de.cotech.hw.openpgp.OpenPgpSecurityKeyConnectionMode;
import de.cotech.hw.openpgp.OpenPgpSecurityKeyConnectionModeConfig;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.SecurityKeyDialogFragment;

import java.io.IOException;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class OpenPgpSecurityKeyDialogFragment extends SecurityKeyDialogFragment<OpenPgpSecurityKey> {
    public static final String ARG_OPENPGP_CONFIG = "de.cotech.hw.ui.ARG_OPENPGP_CONFIG";

    @Override
    public void initConnectionMode(Bundle arguments) {
        OpenPgpSecurityKeyConnectionModeConfig openpgpConfig = arguments.getParcelable(ARG_OPENPGP_CONFIG);
        SecurityKeyManager.getInstance().registerCallback(OpenPgpSecurityKeyConnectionMode.getInstance(openpgpConfig), this, this);
    }

    @Override
    public void updatePinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException {
        OpenPgpSecurityKey openPgpSecurityKey = (OpenPgpSecurityKey) securityKey;
        openPgpSecurityKey.updatePinUsingPuk(puk, newPin);
    }

}
