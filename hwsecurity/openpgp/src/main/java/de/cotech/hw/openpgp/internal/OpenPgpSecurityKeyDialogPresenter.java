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

package de.cotech.hw.openpgp.internal;

import android.content.Context;

import androidx.annotation.RestrictTo;

import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.openpgp.OpenPgpSecurityKey;
import de.cotech.hw.openpgp.R;
import de.cotech.hw.openpgp.exceptions.OpenPgpLockedException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPinTooShortException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPublicKeyUnavailableException;
import de.cotech.hw.openpgp.exceptions.OpenPgpWrongPinException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.SecurityKeyDialogOptions;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;
import de.cotech.hw.util.HwTimber;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class OpenPgpSecurityKeyDialogPresenter extends SecurityKeyDialogPresenter<OpenPgpSecurityKey> {

    public OpenPgpSecurityKeyDialogPresenter(View view, Context context, SecurityKeyDialogOptions options) {
        super(view, context, options);
    }

    @Override
    public void updateSecurityKeyPinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException {
        OpenPgpSecurityKey openPgpSecurityKey = (OpenPgpSecurityKey) securityKey;
        openPgpSecurityKey.updatePinUsingPuk(puk, newPin);
    }

    @Override
    public boolean isSecurityKeyEmpty(SecurityKey securityKey) throws IOException {
        OpenPgpSecurityKey openPgpSecurityKey = (OpenPgpSecurityKey) securityKey;
        return openPgpSecurityKey.isSecurityKeyEmpty();
    }

    @Override
    public void handleError(IOException exception) {
        HwTimber.d(exception);

        switch (currentScreen) {
            case NORMAL_SECURITY_KEY:
            case NORMAL_SECURITY_KEY_HOLD: {
                try {
                    throw exception;
                } catch (OpenPgpLockedException e) {
                    view.updateErrorViewText(R.string.hwsecurity_openpgp_error_no_pin_tries);
                    gotoScreen(Screen.NORMAL_ERROR);
                } catch (OpenPgpWrongPinException e) {
                    if (e.getPinRetriesLeft() == 0) {
                        view.updateErrorViewText(R.string.hwsecurity_openpgp_error_no_pin_tries);
                        gotoScreen(Screen.NORMAL_ERROR);
                    } else {
                        gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_openpgp_error_wrong_pin, e.getPinRetriesLeft()),
                                Screen.NORMAL_ERROR, Screen.NORMAL_ENTER_PIN);
                    }
                } catch (OpenPgpPinTooShortException e) {
                    gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_openpgp_error_too_short_pin),
                            Screen.NORMAL_ERROR, Screen.NORMAL_ENTER_PIN);
                } catch (OpenPgpPublicKeyUnavailableException e) {
                    gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_openpgp_error_no_pubkey),
                            Screen.NORMAL_ERROR, Screen.NORMAL_SECURITY_KEY);
                } catch (SecurityKeyException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_openpgp_error_internal, e.getMessage()));
                    gotoScreen(Screen.NORMAL_ERROR);
                } catch (SecurityKeyDisconnectedException e) {
                    // go back to start if we loose connection
                    gotoScreen(Screen.NORMAL_SECURITY_KEY);
                } catch (IOException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_openpgp_error_internal, e.getMessage()));
                    gotoScreen(Screen.NORMAL_ERROR);
                }
                break;
            }
            case RESET_PIN_SECURITY_KEY: {
                try {
                    throw exception;
                } catch (OpenPgpLockedException e) {
                    view.updateErrorViewText(R.string.hwsecurity_openpgp_error_no_puk_tries);
                    gotoScreen(Screen.RESET_PIN_ERROR);
                } catch (OpenPgpWrongPinException e) {
                    if (e.getPukRetriesLeft() == 0) {
                        view.updateErrorViewText(R.string.hwsecurity_openpgp_error_no_puk_tries);
                        gotoScreen(Screen.RESET_PIN_ERROR);
                    } else {
                        gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_openpgp_error_wrong_puk, e.getPukRetriesLeft()),
                                Screen.RESET_PIN_ERROR, Screen.RESET_PIN_ENTER_PUK);
                    }
                } catch (OpenPgpPinTooShortException e) {
                    gotoErrorScreenAndDelayedScreen(context.getString(R.string.hwsecurity_openpgp_error_too_short_puk),
                            Screen.RESET_PIN_ERROR, Screen.RESET_PIN_ENTER_PUK);
                } catch (SecurityKeyException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_openpgp_error_internal, e.getMessage()));
                    gotoScreen(Screen.RESET_PIN_ERROR);
                } catch (SecurityKeyDisconnectedException e) {
                    // go back to start if we loose connection
                    gotoScreen(Screen.RESET_PIN_SECURITY_KEY);
                } catch (IOException e) {
                    view.updateErrorViewText(context.getString(R.string.hwsecurity_openpgp_error_internal, e.getMessage()));
                    gotoScreen(Screen.RESET_PIN_ERROR);
                }
                break;
            }
            default:
                HwTimber.d("handleError unhandled screen: %s", currentScreen.name());
        }
    }

}
