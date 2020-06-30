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

package de.cotech.hw.fido2.internal;

import android.content.Context;

import androidx.annotation.RestrictTo;

import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.ui.R;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;
import de.cotech.hw.util.HwTimber;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class GenericFido2SecurityKeyDialogPresenter extends SecurityKeyDialogPresenter {

    public GenericFido2SecurityKeyDialogPresenter(View view, Context context, SecurityKeyDialogOptions options) {
        super(view, context, options);
    }

    @Override
    public void handleError(IOException exception) {
        HwTimber.d(exception);

        switch (currentScreen) {
            case NORMAL_SECURITY_KEY:
            case NORMAL_SECURITY_KEY_HOLD: {
                try {
                    throw exception;
                } catch (SecurityKeyException e) {
                    gotoErrorScreenAndDelayedScreen(exception.getMessage(),
                            Screen.NORMAL_ERROR, Screen.NORMAL_SECURITY_KEY);
                } catch (SecurityKeyDisconnectedException e) {
                    gotoScreen(Screen.NORMAL_SECURITY_KEY);
                } catch (IOException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_fido_error_internal, e.getMessage()));
                    gotoScreen(Screen.NORMAL_ERROR);
                }
                break;
            }
            default:
                HwTimber.d("handleError unhandled screen: %s", currentScreen.name());
        }
    }

    @Override
    public void updateSecurityKeyPinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException {
        throw new IOException("RESET_PIN mode is not supported in FIDO2 mode");
    }

    @Override
    public boolean isSecurityKeyEmpty(SecurityKey securityKey) throws IOException {
        HwTimber.e("SETUP mode is not supported in FIDO2 mode");
        return true;
    }

}
