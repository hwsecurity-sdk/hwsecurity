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

package de.cotech.hw.ui;

import android.os.Bundle;
import androidx.annotation.NonNull;
import de.cotech.hw.openpgp.OpenPgpSecurityKey;
import de.cotech.hw.openpgp.OpenPgpSecurityKeyConnectionModeConfig;
//import de.cotech.hw.piv.PivSecurityKey;
import de.cotech.hw.ui.internal.OpenPgpSecurityKeyDialogFragment;
//import de.cotech.hw.ui.internal.PivSecurityKeyDialogFragment;

public class SecurityKeyDialogFactory {

    public static SecurityKeyDialogFragment<OpenPgpSecurityKey> newOpenPgpInstance() {
        return newOpenPgpInstance(SecurityKeyDialogOptions.builder().build(), new OpenPgpSecurityKeyConnectionModeConfig.Builder().build());
    }

    public static SecurityKeyDialogFragment<OpenPgpSecurityKey> newOpenPgpInstance(@NonNull SecurityKeyDialogOptions options) {
        return newOpenPgpInstance(options, new OpenPgpSecurityKeyConnectionModeConfig.Builder().build());
    }

    public static SecurityKeyDialogFragment<OpenPgpSecurityKey> newOpenPgpInstance(@NonNull SecurityKeyDialogOptions options, @NonNull OpenPgpSecurityKeyConnectionModeConfig openpgpConfig) {
        try {
            Class.forName("de.cotech.hw.openpgp.OpenPgpSecurityKey");
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("You must include the hwsecurity-openpgp Maven artifact!");
        }

        Bundle args = new Bundle();
        args.putParcelable(OpenPgpSecurityKeyDialogFragment.ARG_DIALOG_OPTIONS, options);
        args.putParcelable(OpenPgpSecurityKeyDialogFragment.ARG_OPENPGP_CONFIG, openpgpConfig);

        OpenPgpSecurityKeyDialogFragment fragment = new OpenPgpSecurityKeyDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

//     public static SecurityKeyDialogFragment<PivSecurityKey> newPivInstance() {
//         return newPivInstance(SecurityKeyDialogOptions.builder().build());
//     }
// 
//     public static SecurityKeyDialogFragment<PivSecurityKey> newPivInstance(@NonNull SecurityKeyDialogOptions options) {
//         try {
//             Class.forName("de.cotech.hw.piv.PivSecurityKey");
//         } catch (ClassNotFoundException e) {
//             throw new IllegalArgumentException("You must include the hwsecurity-piv Maven artifact!");
//         }
// 
//         Bundle args = new Bundle();
//         args.putParcelable(PivSecurityKeyDialogFragment.ARG_DIALOG_OPTIONS, options);
// 
//         PivSecurityKeyDialogFragment fragment = new PivSecurityKeyDialogFragment();
//         fragment.setArguments(args);
//         return fragment;
//     }

}
