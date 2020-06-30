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

package de.cotech.hw.fido2.ui;

import android.content.Context;
import android.os.Bundle;

import androidx.annotation.NonNull;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.fido2.Fido2SecurityKey;
import de.cotech.hw.fido2.Fido2SecurityKeyConnectionMode;
import de.cotech.hw.fido2.Fido2SecurityKeyConnectionModeConfig;
import de.cotech.hw.fido2.internal.GenericFido2SecurityKeyDialogPresenter;
import de.cotech.hw.ui.SecurityKeyDialogFragment;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;

public class GenericFido2SecurityKeyDialogFragment extends SecurityKeyDialogFragment<Fido2SecurityKey> {
    public static final String ARG_FIDO2_CONFIG = "de.cotech.hw.fido2.ARG_FIDO2_CONFIG";

    public static SecurityKeyDialogFragment<Fido2SecurityKey> newInstance() {
        return newInstance(SecurityKeyDialogOptions.builder().build(), Fido2SecurityKeyConnectionModeConfig.getDefaultConfig());
    }

    public static SecurityKeyDialogFragment<Fido2SecurityKey> newInstance(@NonNull SecurityKeyDialogOptions options) {
        return newInstance(options, Fido2SecurityKeyConnectionModeConfig.getDefaultConfig());
    }

    public static SecurityKeyDialogFragment<Fido2SecurityKey> newInstance(@NonNull SecurityKeyDialogOptions options, @NonNull Fido2SecurityKeyConnectionModeConfig fido2Config) {
        try {
            Class.forName("de.cotech.hw.ui.SecurityKeyDialogFragment");
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("You must include the hwsecurity-ui Maven artifact!");
        }

        Bundle args = new Bundle();
        args.putParcelable(GenericFido2SecurityKeyDialogFragment.ARG_DIALOG_OPTIONS, options);
        args.putParcelable(GenericFido2SecurityKeyDialogFragment.ARG_FIDO2_CONFIG, fido2Config);

        GenericFido2SecurityKeyDialogFragment fragment = new GenericFido2SecurityKeyDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void initSecurityKeyConnectionMode(Bundle arguments) {
        Fido2SecurityKeyConnectionModeConfig fido2Config = arguments.getParcelable(ARG_FIDO2_CONFIG);
        SecurityKeyManager.getInstance().registerCallback(new Fido2SecurityKeyConnectionMode(fido2Config), this, this);
    }

    @Override
    public SecurityKeyDialogPresenter initPresenter(SecurityKeyDialogPresenter.View view, Context context, SecurityKeyDialogOptions options) {
        return new GenericFido2SecurityKeyDialogPresenter(this, getActivity(), options);
    }

}
