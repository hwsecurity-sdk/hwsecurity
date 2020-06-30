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

package de.cotech.hw.piv.internal;

import android.content.Context;

import androidx.annotation.RestrictTo;

import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.piv.PivSecurityKey;
import de.cotech.hw.piv.R;
import de.cotech.hw.piv.exceptions.PivWrongPinException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;
import de.cotech.hw.util.HwTimber;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class PivSecurityKeyDialogPresenter extends SecurityKeyDialogPresenter {

    public PivSecurityKeyDialogPresenter(View view, Context context, SecurityKeyDialogOptions options) {
        super(view, context, options);
    }

    @Override
    public void updateSecurityKeyPinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException {
        PivSecurityKey pivSecurityKey = (PivSecurityKey) securityKey;
        pivSecurityKey.updatePinUsingPuk(puk, newPin);
    }

    @Override
    public boolean isSecurityKeyEmpty(SecurityKey securityKey) throws IOException {
        HwTimber.e("SETUP mode is not supported in PIV mode");
        return true;
    }

    @Override
    public void handleError(IOException exception) {
        HwTimber.d(exception);

        switch (currentScreen) {
            case NORMAL_SECURITY_KEY:
            case NORMAL_SECURITY_KEY_HOLD: {
                try {
                    throw exception;
                } catch (PivWrongPinException e) {
                    gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_piv_error_wrong_pin, e.getRetriesLeft()),
                            Screen.NORMAL_ERROR, Screen.NORMAL_ENTER_PIN);
                } catch (SecurityKeyException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_piv_error_internal, e.getMessage()));
                    gotoScreen(Screen.NORMAL_ERROR);
                } catch (SecurityKeyDisconnectedException e) {
                    // go back to start if we loose connection
                    gotoScreen(Screen.NORMAL_SECURITY_KEY);
                } catch (IOException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_piv_error_internal, e.getMessage()));
                    gotoScreen(Screen.NORMAL_ERROR);
                }
                break;
            }
            case RESET_PIN_SECURITY_KEY: {
                try {
                    throw exception;
                } catch (PivWrongPinException e) {
                    gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_piv_error_wrong_puk, e.getRetriesLeft()),
                            Screen.RESET_PIN_ERROR, Screen.RESET_PIN_ENTER_PUK);
                } catch (SecurityKeyException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_piv_error_internal, e.getMessage()));
                    gotoScreen(Screen.RESET_PIN_ERROR);
                } catch (SecurityKeyDisconnectedException e) {
                    // go back to start if we loose connection
                    gotoScreen(Screen.RESET_PIN_SECURITY_KEY);
                } catch (IOException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_piv_error_internal, e.getMessage()));
                    gotoScreen(Screen.RESET_PIN_ERROR);
                }
                break;
            }
            default:
                HwTimber.d("handleError unhandled screen: %s", currentScreen.name());
        }
    }

}
