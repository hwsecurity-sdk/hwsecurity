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

import android.content.Context;
import android.os.Bundle;

import androidx.annotation.NonNull;

import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.openpgp.internal.OpenPgpSecurityKeyDialogPresenter;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.SecurityKeyDialogFragment;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;

public class OpenPgpSecurityKeyDialogFragment extends SecurityKeyDialogFragment<OpenPgpSecurityKey> {
    public static final String ARG_OPENPGP_CONFIG = "de.cotech.hw.openpgp.ARG_OPENPGP_CONFIG";

    public static SecurityKeyDialogFragment<OpenPgpSecurityKey> newInstance() {
        return newInstance(SecurityKeyDialogOptions.builder().build(), new OpenPgpSecurityKeyConnectionModeConfig.Builder().build());
    }

    public static SecurityKeyDialogFragment<OpenPgpSecurityKey> newInstance(@NonNull SecurityKeyDialogOptions options) {
        return newInstance(options, new OpenPgpSecurityKeyConnectionModeConfig.Builder().build());
    }

    public static SecurityKeyDialogFragment<OpenPgpSecurityKey> newInstance(@NonNull SecurityKeyDialogOptions options, @NonNull OpenPgpSecurityKeyConnectionModeConfig openpgpConfig) {
        try {
            Class.forName("de.cotech.hw.ui.SecurityKeyDialogFragment");
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("You must include the hwsecurity-ui Maven artifact!");
        }

        Bundle args = new Bundle();
        args.putParcelable(OpenPgpSecurityKeyDialogFragment.ARG_DIALOG_OPTIONS, options);
        args.putParcelable(OpenPgpSecurityKeyDialogFragment.ARG_OPENPGP_CONFIG, openpgpConfig);

        OpenPgpSecurityKeyDialogFragment fragment = new OpenPgpSecurityKeyDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void initSecurityKeyConnectionMode(Bundle arguments) {
        OpenPgpSecurityKeyConnectionModeConfig openpgpConfig = arguments.getParcelable(ARG_OPENPGP_CONFIG);
        SecurityKeyManager.getInstance().registerCallback(OpenPgpSecurityKeyConnectionMode.getInstance(openpgpConfig), this, this);
    }

    @Override
    public SecurityKeyDialogPresenter initPresenter(SecurityKeyDialogPresenter.View view, Context context, SecurityKeyDialogOptions options) {
        return new OpenPgpSecurityKeyDialogPresenter(this, getActivity(), options);
    }

}
