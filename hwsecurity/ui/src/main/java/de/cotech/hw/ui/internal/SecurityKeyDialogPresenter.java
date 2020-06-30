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

package de.cotech.hw.ui.internal;

import android.content.Context;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;

import java.io.IOException;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.ByteSecretGenerator;
import de.cotech.hw.secrets.PinProvider;
import de.cotech.hw.secrets.StaticPinProvider;
import de.cotech.hw.ui.R;
import de.cotech.hw.ui.SecurityKeyDialogOptions;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public abstract class SecurityKeyDialogPresenter<T extends SecurityKey> {

    protected static final int SETUP_DEFAULT_PIN_LENGTH = 6;
    protected static final int SETUP_DEFAULT_PUK_LENGTH = 8;

    protected static final long TIME_DELAYED_SCREEN_CHANGE = 3000;

    protected Context context;
    protected View view;
    protected SecurityKeyDialogOptions options;

    protected KeyboardPreferenceRepository keyboardPreferenceRepository;

    protected StaticPinProvider staticPinProvider;

    protected ByteSecret resetNewPinSecret;
    protected ByteSecret resetPukSecret;
    protected ByteSecret setupPinSecret;

    protected enum Screen {
        NORMAL_ENTER_PIN,
        NORMAL_SECURITY_KEY,
        NORMAL_SECURITY_KEY_HOLD,
        NORMAL_ERROR,
        RESET_PIN_ENTER_PUK,
        RESET_PIN_ENTER_NEW_PIN,
        RESET_PIN_SECURITY_KEY,
        RESET_PIN_SUCCESS,
        RESET_PIN_ERROR,
        SETUP_CHOOSE_PIN,
        SETUP_SHOW_PUK,
        SETUP_CONFIRM_WIPE,
    }

    protected Screen currentScreen;

    public SecurityKeyDialogPresenter(View view, Context context, SecurityKeyDialogOptions options) {
        this.view = view;
        this.context = context;
        this.options = options;

        keyboardPreferenceRepository = new KeyboardPreferenceRepository(context);
    }

    // functions are implemented in the specific presenters for each protocol, such as OpenPGP, PIV
    abstract public void handleError(IOException exception);

    abstract public void updateSecurityKeyPinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException;

    abstract public boolean isSecurityKeyEmpty(SecurityKey securityKey) throws IOException;

    public void cancel() {
        view.cancel();
    }

    public void resetPinScreen() {
        gotoScreen(Screen.RESET_PIN_ENTER_PUK);
    }

    public void finishedWithPuk() {
        gotoScreen(Screen.NORMAL_SECURITY_KEY);
    }

    public void gotoScreenOnCreate() {
        switch (options.getPinMode()) {
            case PIN_INPUT: {
                gotoScreen(Screen.NORMAL_ENTER_PIN);
                break;
            }
            case NO_PIN_INPUT: {
                gotoScreen(Screen.NORMAL_SECURITY_KEY);
                break;
            }
            case RESET_PIN: {
                gotoScreen(Screen.RESET_PIN_ENTER_PUK);
                break;
            }
            case SETUP: {
                gotoScreen(Screen.SETUP_CHOOSE_PIN);
                break;
            }
            default: {
                throw new IllegalArgumentException("unknown PinMode!");
            }
        }
    }

    public void onPinEntered(ByteSecret pinSecret) {
        // stay on this screen if no PIN is entered
        if (pinSecret == null) {
            return;
        }

        switch (currentScreen) {
            case NORMAL_ENTER_PIN: {
                staticPinProvider = StaticPinProvider.getInstance(pinSecret);
                gotoScreen(Screen.NORMAL_SECURITY_KEY);
                break;
            }
            case RESET_PIN_ENTER_PUK: {
                resetPukSecret = pinSecret;
                gotoScreen(Screen.RESET_PIN_ENTER_NEW_PIN);
                break;
            }
            case RESET_PIN_ENTER_NEW_PIN: {
                resetNewPinSecret = pinSecret;
                gotoScreen(Screen.RESET_PIN_SECURITY_KEY);
                break;
            }
            case SETUP_CHOOSE_PIN: {
                setupPinSecret = pinSecret;
                gotoScreen(Screen.SETUP_SHOW_PUK);
                break;
            }
            default: {
                // do nothing
                break;
            }
        }
    }

    protected void gotoScreen(Screen newScreen) {
        gotoScreen(newScreen, true);
    }

    protected void gotoScreen(Screen newScreen, boolean isTransportNfc) {
        switch (newScreen) {
            case NORMAL_ENTER_PIN: {
                view.updateTitle(getTitle(), R.string.hwsecurity_ui_description_enter_pin);
                view.screenEnterPin(options.getPinLength(), options.getShowReset(), options.getAllowKeyboard());
                break;
            }
            case NORMAL_SECURITY_KEY: {
                view.updateTitle(getTitle(), R.string.hwsecurity_ui_description_start);
                view.screenSecurityKey(options.getPinLength(), options.getFormFactor());
                break;
            }
            case NORMAL_SECURITY_KEY_HOLD: {
                int descriptionResId = isTransportNfc ? R.string.hwsecurity_ui_description_hold_nfc : R.string.hwsecurity_ui_description_hold_usb;
                view.updateTitle(getTitle(), descriptionResId);
                view.screenHoldSecurityKey();
                break;
            }
            case RESET_PIN_ENTER_PUK: {
                view.updateTitle(R.string.hwsecurity_ui_title_reset_pin, R.string.hwsecurity_ui_description_enter_puk);
                view.screenResetPinEnterPinOrPuk(options.getPukLength());
                break;
            }
            case RESET_PIN_ENTER_NEW_PIN: {
                view.updateTitle(R.string.hwsecurity_ui_title_reset_pin, R.string.hwsecurity_ui_description_enter_new_pin);
                view.screenResetPinEnterPinOrPuk(options.getPinLength());
                break;
            }
            case RESET_PIN_SECURITY_KEY: {
                view.updateTitle(R.string.hwsecurity_ui_title_reset_pin, R.string.hwsecurity_ui_description_hold_nfc);
                view.screenResetPinSecurityKey(options.getFormFactor());
                break;
            }
            case RESET_PIN_SUCCESS: {
                view.updateTitle(R.string.hwsecurity_ui_title_reset_pin, "");
                view.screenResetPinSuccess();
                break;
            }
            case NORMAL_ERROR:
            case RESET_PIN_ERROR: {
                view.screenError();
                break;
            }
            case SETUP_CHOOSE_PIN: {
                int pinLength = options.getPinLength() == null ? SETUP_DEFAULT_PIN_LENGTH : options.getPinLength();

                view.updateTitle(getTitle(), R.string.hwsecurity_ui_description_choose_pin);
                view.screenSetupChoosePin(pinLength);
                break;
            }
            case SETUP_SHOW_PUK: {
                int pukLength = options.getPukLength() == null ? SETUP_DEFAULT_PUK_LENGTH : options.getPukLength();
                ByteSecret setupPuk = ByteSecretGenerator.getInstance().createRandomNumeric(pukLength);
                staticPinProvider = StaticPinProvider.getInstance(setupPinSecret, setupPuk);

                view.updateTitle(getTitle(), R.string.hwsecurity_ui_description_puk);
                view.screenSetupChoosePuk(pukLength, setupPuk);
                break;
            }
            case SETUP_CONFIRM_WIPE: {
                view.updateTitle(getTitle(), "");
                view.screenConfirmWipe();
                break;
            }
        }

        currentScreen = newScreen;
    }

    public void switchBetweenPinInputs() {
        boolean isKeyboardPreferred = keyboardPreferenceRepository.isKeyboardPreferred();

        if (isKeyboardPreferred) {
            keyboardPreferenceRepository.setIsKeyboardPreferred(false);
            view.showKeypadPinInput();
        } else {
            keyboardPreferenceRepository.setIsKeyboardPreferred(true);
            view.showKeyboardPinInput();
        }
    }

    public void showPinInput() {
        boolean isKeyboardPreferred = keyboardPreferenceRepository.isKeyboardPreferred();

        if (isKeyboardPreferred) {
            view.showKeyboardPinInput();
        } else {
            view.showKeypadPinInput();
        }
    }

    private String getTitle() {
        if (options.getTitle() != null) {
            return options.getTitle();
        }
        switch (options.getPinMode()) {
            case PIN_INPUT: {
                return context.getString(R.string.hwsecurity_ui_title_login);
            }
            case NO_PIN_INPUT: {
                return context.getString(R.string.hwsecurity_ui_title_add);
            }
            case RESET_PIN: {
                return context.getString(R.string.hwsecurity_ui_title_reset_pin);
            }
            case SETUP: {
                return context.getString(R.string.hwsecurity_ui_title_setup);
            }
            default: {
                throw new IllegalArgumentException("unknown PinMode!");
            }
        }
    }

    public void onSecurityKeyDiscovered(@NonNull SecurityKey securityKey,
                                        boolean isWipedConfirmed) {

        switch (currentScreen) {
            case NORMAL_ENTER_PIN: {
                // Only stay in this screen for USB. Automatically proceed with entered PIN on NFC connection
                if (!securityKey.isTransportNfc()) {
                    break;
                }
                view.confirmPinInput();
                // fall-through
            }
            case SETUP_CONFIRM_WIPE:
                // fall-through
            case NORMAL_SECURITY_KEY:
                // fall-through
            case NORMAL_SECURITY_KEY_HOLD: {
                gotoScreen(Screen.NORMAL_SECURITY_KEY_HOLD, securityKey.isTransportNfc());

                boolean isSetupMode = options.getPinMode() == SecurityKeyDialogOptions.PinMode.SETUP;
                if (isSetupMode && !isWipedConfirmed) {
                    try {
                        if (!isSecurityKeyEmpty(securityKey)) {
                            gotoScreen(Screen.SETUP_CONFIRM_WIPE);
                            return;
                        }
                    } catch (IOException e) {
                        handleError(e);
                    }
                }

                try {
                    view.onSecurityKeyDialogDiscoveredCallback(securityKey, staticPinProvider);
                } catch (IOException e) {
                    handleError(e);
                    return;
                }
                break;
            }
            case RESET_PIN_SECURITY_KEY: {
                new Thread(() -> {
                    try {
                        updateSecurityKeyPinUsingPuk(securityKey, resetPukSecret, resetNewPinSecret);

                        view.postRunnable(() -> Toast.makeText(context, R.string.hwsecurity_ui_changed_pin, Toast.LENGTH_LONG).show());
                        view.postRunnable(() -> gotoScreen(Screen.RESET_PIN_SUCCESS));
                        view.postDelayedRunnable(() -> {
                            if (options.getPinMode() == SecurityKeyDialogOptions.PinMode.RESET_PIN) {
                                view.cancel();
                            } else {
                                gotoScreen(Screen.NORMAL_ENTER_PIN);
                            }
                        }, TIME_DELAYED_SCREEN_CHANGE);
                    } catch (IOException e) {
                        view.postRunnable(() -> handleError(e));
                    }
                }).start();
                break;
            }
            default:
                // do nothing
        }
    }

    protected void gotoErrorScreenAndDelayedScreen(String text, Screen errorScreen, Screen delayedScreen) {
        view.updateErrorViewText(text);
        gotoScreen(errorScreen);
        view.postDelayedRunnable(() -> gotoScreen(delayedScreen), TIME_DELAYED_SCREEN_CHANGE);
    }

    public interface View {

        void showKeypadPinInput();

        void showKeyboardPinInput();

        void confirmPinInput();

        void cancel();

        void updateErrorViewText(String text);

        void updateErrorViewText(int text);

        boolean postRunnable(Runnable action);

        boolean postDelayedRunnable(Runnable action, long delayMillis);

        void updateTitle(String title, int descriptionResId);

        void updateTitle(int titleResId, String description);

        void updateTitle(int titleResId, int descriptionResId);

        void updateTitle(String title, String description);

        void screenEnterPin(Integer pinLength, boolean showReset, boolean useKeyboard);

        void screenSecurityKey(Integer pinLength, SecurityKeyDialogOptions.FormFactor formFactor);

        void screenHoldSecurityKey();

        void screenResetPinEnterPinOrPuk(Integer pinLength);

        void screenResetPinSecurityKey(SecurityKeyDialogOptions.FormFactor formFactor);

        void screenResetPinSuccess();

        void screenError();

        void screenSetupChoosePin(int pinLength);

        void screenSetupChoosePuk(int pukLength, ByteSecret setupPuk);

        void screenConfirmWipe();

        void onSecurityKeyDialogDiscoveredCallback(@NonNull SecurityKey securityKey, @Nullable PinProvider pinProvider) throws IOException;

    }
}
