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

import android.content.Context;
import android.os.Bundle;

import androidx.annotation.NonNull;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.piv.internal.PivSecurityKeyDialogPresenter;
import de.cotech.hw.ui.SecurityKeyDialogFragment;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;

public class PivSecurityKeyDialogFragment extends SecurityKeyDialogFragment<PivSecurityKey> {

    public static SecurityKeyDialogFragment<PivSecurityKey> newInstance() {
        return newInstance(SecurityKeyDialogOptions.builder().build());
    }

    public static SecurityKeyDialogFragment<PivSecurityKey> newInstance(@NonNull SecurityKeyDialogOptions options) {
        try {
            Class.forName("de.cotech.hw.ui.SecurityKeyDialogFragment");
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("You must include the hwsecurity-ui Maven artifact!");
        }

        Bundle args = new Bundle();
        args.putParcelable(PivSecurityKeyDialogFragment.ARG_DIALOG_OPTIONS, options);

        PivSecurityKeyDialogFragment fragment = new PivSecurityKeyDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void initSecurityKeyConnectionMode(Bundle arguments) {
        SecurityKeyManager.getInstance().registerCallback(new PivSecurityKeyConnectionMode(), this, this);
    }

    @Override
    public SecurityKeyDialogPresenter initPresenter(SecurityKeyDialogPresenter.View view, Context context, SecurityKeyDialogOptions options) {
        return new PivSecurityKeyDialogPresenter(this, getActivity(), options);
    }

}
