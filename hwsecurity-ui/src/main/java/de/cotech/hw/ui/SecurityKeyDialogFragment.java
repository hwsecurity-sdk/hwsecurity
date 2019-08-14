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


import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.ActivityInfo;
import android.nfc.TagLostException;
import android.os.Bundle;
import android.view.*;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.UiThread;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.transition.TransitionManager;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.button.MaterialButton;
import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyCallback;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.openpgp.exceptions.OpenPgpCardBlockedException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPinTooShortException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPublicKeyUnavailableException;
import de.cotech.hw.openpgp.exceptions.OpenPgpWrongPinException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.StaticPinProvider;
import de.cotech.hw.ui.internal.*;
import de.cotech.hw.util.HwTimber;

import java.io.IOException;
import java.util.Objects;

/**
 * This dialog shows helpful animations and handles all the PIN/PUK input for you.
 * It still allows you full control over the operations you can execute on the Security Key.
 * <p>
 * Use the SecurityKeyDialogFactory to instantiate this.
 */
public abstract class SecurityKeyDialogFragment<T extends SecurityKey> extends BottomSheetDialogFragment
        implements SecurityKeyCallback<T>, PinInputCallback, SecurityKeyDialogInterface {
    @SuppressWarnings("WeakerAccess") // public API
    public static final String FRAGMENT_TAG = "security-key-dialog-fragment";
    public static final String ARG_DIALOG_OPTIONS = "de.cotech.hw.ui.ARG_DIALOG_OPTIONS";

    private static final long TIME_DELAYED_STATE_CHANGE = 3000;

    private static final String PREFERENCES_NAME = "hwsecurity_ui_preferences";
    private static final String PREFERENCES_KEY_KEYBOARD_PREFERRED = "keyboard_preferred";

    private SecurityKeyDialogOptions options;

    private SecurityKeyDialogInterface.SecurityKeyDialogCallback callback;

    private CoordinatorLayout coordinator;
    private FrameLayout bottomSheet;
    private ConstraintLayout innerBottomSheet;
    private TextView textViewTitle;
    private TextView textViewDescription;
    private ProgressBar smartcardProgress;
    private ImageView errorImage;
    private TextView errorText;

    private MaterialButton buttonCancel;
    private MaterialButton buttonResetPin;
    private MaterialButton buttonKeyboardSwitch;

    private StaticPinProvider staticPinProvider;

    private ByteSecret resetNewPinSecret;
    private ByteSecret resetPukSecret;

    private SecurityKeyFormFactor securityKeyFormFactor;
    private SmartcardFormFactor smartcardFormFactor;

    private KeypadPinInput keypadPinInput;
    private KeyboardPinInput keyboardPinInput;

    private Guideline guidelineForceHeight;

    private enum State {
        NORMAL_ENTER_PIN,
        NORMAL_SMARTCARD,
        NORMAL_SMARTCARD_HOLD,
        NORMAL_ERROR,
        RESET_ENTER_PUK,
        RESET_ENTER_NEW_PIN,
        RESET_SMARTCARD,
        RESET_SUCCESS,
        RESET_ERROR
    }

    private State currentState;

    abstract public void initConnectionMode(Bundle arguments);

    abstract public void updatePinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException;

    public void setSecurityKeyDialogCallback(SecurityKeyDialogInterface.SecurityKeyDialogCallback callback) {
        this.callback = callback;
    }

    public void show(FragmentManager fragmentManager) {
        Fragment fragment = fragmentManager.findFragmentByTag(FRAGMENT_TAG);
        if (fragment == null) {
            show(fragmentManager, FRAGMENT_TAG);
        }
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        BottomSheetDialog dialog = (BottomSheetDialog) super.onCreateDialog(savedInstanceState);

        dialog.setOnShowListener(d -> {
            BottomSheetDialog bottomSheetDialog = (BottomSheetDialog) d;

            coordinator = bottomSheetDialog.findViewById(com.google.android.material.R.id.coordinator);
            bottomSheet = bottomSheetDialog.findViewById(com.google.android.material.R.id.design_bottom_sheet);

            if (bottomSheet == null) {
                throw new IllegalStateException("bottomSheet is null");
            }

            // never just "peek", always fully expand the bottom sheet
            BottomSheetBehavior bottomSheetBehavior = BottomSheetBehavior.from(bottomSheet);
            bottomSheetBehavior.setSkipCollapsed(true);
            bottomSheetBehavior.setState(BottomSheetBehavior.STATE_EXPANDED);
        });

        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Bundle arguments = getArguments();
        if (arguments == null) {
            throw new IllegalStateException("Do not create SecurityKeyDialogFragment directly, use static .newInstance() methods!");
        }
        options = arguments.getParcelable(ARG_DIALOG_OPTIONS);
        if (options == null) {
            throw new IllegalStateException("Do not create SecurityKeyDialogFragment directly, use static .newInstance() methods!");
        }

        setStyle(STYLE_NORMAL, options.getTheme());

        initConnectionMode(arguments);

        Context context = getContext();
        if (callback == null) {
            if (context instanceof SecurityKeyDialogInterface.SecurityKeyDialogCallback) {
                setSecurityKeyDialogCallback((SecurityKeyDialogInterface.SecurityKeyDialogCallback) context);
            }
        }

        if (callback == null) {
            if (savedInstanceState != null) {
                HwTimber.e("Dismissing SecurityKeyDialogFragment left without callbacks after configuration change!");
                dismiss();
                return;
            }
            throw new IllegalStateException("Activity must implement SecurityKeyDialogInterface.SecurityKeyDialogCallback!");
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.hwsecurity_security_key_dialog, container, false);
    }

    @Override
    public void onDetach() {
        super.onDetach();
        FragmentActivity activity = getActivity();
        if (activity != null) {
            int changingConfigurations = activity.getChangingConfigurations();
            int keyboardChanges = ActivityInfo.CONFIG_KEYBOARD | ActivityInfo.CONFIG_KEYBOARD_HIDDEN;
            boolean isKeyboardConfigChange = (changingConfigurations & keyboardChanges) != 0;
            if (isKeyboardConfigChange) {
                HwTimber.e("Activity is recreated due to a keyboard config change, which may cause UI flickering!\n" +
                        "To fix this issue, the Activity's configChanges attribute " +
                        "in AndroidManifest.xml should include keyboard|keyboardHidden");
            }
        }
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        if (options.getPreventScreenshots()) {
            // prevent screenshots
            Window window = Objects.requireNonNull(getDialog().getWindow());
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }

        innerBottomSheet = view.findViewById(R.id.hwSecurityDialogBottomSheet);
        buttonCancel = view.findViewById(R.id.buttonCancel);
        buttonResetPin = view.findViewById(R.id.buttonResetPin);
        buttonKeyboardSwitch = view.findViewById(R.id.buttonKeyboardSwitch);

        textViewTitle = view.findViewById(R.id.textTitle);
        textViewDescription = view.findViewById(R.id.textDescription);
        smartcardProgress = view.findViewById(R.id.securityKeyProgressBar);
        errorImage = view.findViewById(R.id.errorImage);
        errorText = view.findViewById(R.id.errorText);
        guidelineForceHeight = view.findViewById(R.id.guidelineForceHeight);

        buttonCancel.setOnClickListener(v -> cancel());
        buttonResetPin.setOnClickListener(v -> gotoState(State.RESET_ENTER_PUK));
        buttonKeyboardSwitch.setOnClickListener(v -> showHidePinInput(!isKeyboardPreferred()));

        keypadPinInput = new KeypadPinInput(view.findViewById(R.id.includeKeypadInput));
        keypadPinInput.reset(options.getPinLength());
        keypadPinInput.setPinInputCallback(this);

        keyboardPinInput = new KeyboardPinInput(view.findViewById(R.id.includeKeyboardInput));
        keyboardPinInput.setPinInputCallback(this);

        smartcardFormFactor = new SmartcardFormFactor(view.findViewById(R.id.includeSmartcardFormFactor));
        securityKeyFormFactor = new SecurityKeyFormFactor(view.findViewById(R.id.includeSecurityKeyFormFactor), innerBottomSheet);

        switch (options.getPinMode()) {
            case PIN_INPUT: {
                gotoState(State.NORMAL_ENTER_PIN);
                break;
            }
            case NO_PIN_INPUT: {
                gotoState(State.NORMAL_SMARTCARD);
                break;
            }
            default: {
                throw new IllegalArgumentException("unknown PinMode!");
            }
        }
    }

    private void showHidePinInput(boolean isKeyboardPreferred) {
        if (isKeyboardPreferred) {
            keyboardPinInput.setVisibility(View.VISIBLE);
            keypadPinInput.setVisibility(View.GONE);
            buttonKeyboardSwitch.setIcon(getResources().getDrawable(R.drawable.hwsecurity_ic_keyboard_numeric));
            keyboardPinInput.openKeyboard();
            setIsKeyboardPreferred(true);
        } else {
            keyboardPinInput.setVisibility(View.GONE);
            keypadPinInput.setVisibility(View.VISIBLE);
            buttonKeyboardSwitch.setIcon(getResources().getDrawable(R.drawable.hwsecurity_ic_keyboard_alphabetical));
            setIsKeyboardPreferred(false);
        }
    }

    private boolean isKeyboardPreferred() {
        @SuppressWarnings("ConstantConditions")
        SharedPreferences preferences = getContext().getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
        if (preferences == null) {
            return false;
        }
        return preferences.getBoolean(PREFERENCES_KEY_KEYBOARD_PREFERRED, false);
    }

    private void setIsKeyboardPreferred(boolean isKeyboardPreferred) {
        @SuppressWarnings("ConstantConditions")
        SharedPreferences preferences = getContext().getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE);
        if (preferences == null) {
            return;
        }

        preferences.edit()
                .putBoolean(PREFERENCES_KEY_KEYBOARD_PREFERRED, isKeyboardPreferred)
                .apply();
    }

    @Override
    public void cancel() {
        getDialog().cancel();
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        if (callback != null) {
            callback.onSecurityKeyDialogCancel();
        }
    }

    @Override
    public void onDismiss(DialogInterface dialog) {
        super.onDismiss(dialog);
        if (callback != null) {
            callback.onSecurityKeyDialogDismiss();
        }
    }

    @Override
    public void onPinEntered(ByteSecret pinSecret) {
        switch (currentState) {
            case NORMAL_ENTER_PIN: {
                staticPinProvider = StaticPinProvider.getInstance(pinSecret);
                gotoState(State.NORMAL_SMARTCARD);
                break;
            }
            case RESET_ENTER_PUK: {
                resetPukSecret = pinSecret;
                gotoState(State.RESET_ENTER_NEW_PIN);
                break;
            }
            case RESET_ENTER_NEW_PIN: {
                resetNewPinSecret = pinSecret;
                gotoState(State.RESET_SMARTCARD);
                break;
            }
            default: {
                // do nothing
                break;
            }
        }
    }

    private void gotoState(State newState) {
        switch (newState) {
            case NORMAL_ENTER_PIN: {
                keypadPinInput.reset(options.getPinLength());
                textViewTitle.setText((options.getTitle() != null) ? options.getTitle() : getString(R.string.hwsecurity_ui_title));
                textViewDescription.setText(R.string.hwsecurity_ui_description_enter_pin);

                showHidePinInput(isKeyboardPreferred());
                buttonKeyboardSwitch.setVisibility(options.getAllowKeyboard() ? View.VISIBLE : View.GONE);
                buttonResetPin.setVisibility(options.getShowReset() ? View.VISIBLE : View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.GONE);
                break;
            }
            case NORMAL_SMARTCARD: {
                SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();

                keypadPinInput.reset(options.getPinLength());
                textViewTitle.setText((options.getTitle() != null) ? options.getTitle() : getString(R.string.hwsecurity_ui_title));
                textViewDescription.setText(R.string.hwsecurity_ui_description_smartcard);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                boolean isSmartcardFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SMART_CARD;
                boolean isSecurityKeyFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SECURITY_KEY;
                smartcardFormFactor.setVisibility(isSmartcardFormFactor ? View.VISIBLE : View.GONE);
                securityKeyFormFactor.setVisibility(isSecurityKeyFormFactor ? View.VISIBLE : View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.GONE);
                if (isSmartcardFormFactor) {
                    smartcardFormFactor.startSmartcardAnimation();
                }
                break;
            }
            case NORMAL_SMARTCARD_HOLD: {
                textViewTitle.setText((options.getTitle() != null) ? options.getTitle() : getString(R.string.hwsecurity_ui_title));
                textViewDescription.setText(R.string.hwsecurity_ui_description_hold_nfc);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.VISIBLE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.GONE);
                break;
            }
            case RESET_ENTER_PUK: {
                keypadPinInput.reset(options.getPukLength());
                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText(R.string.hwsecurity_ui_description_enter_puk);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.VISIBLE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.GONE);
                break;
            }
            case RESET_ENTER_NEW_PIN: {
                keypadPinInput.reset(options.getPinLength());
                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText(R.string.hwsecurity_ui_description_enter_new_pin);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.VISIBLE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.GONE);
                break;
            }
            case RESET_SMARTCARD: {
                SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();

                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText(R.string.hwsecurity_ui_description_hold_nfc);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                boolean isSmartcardFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SMART_CARD;
                boolean isSecurityKeyFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SECURITY_KEY;
                smartcardFormFactor.setVisibility(isSmartcardFormFactor ? View.VISIBLE : View.GONE);
                securityKeyFormFactor.setVisibility(isSecurityKeyFormFactor ? View.VISIBLE : View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.GONE);
                if (isSmartcardFormFactor) {
                    smartcardFormFactor.startSmartcardAnimation();
                }
                break;
            }
            case RESET_SUCCESS: {
                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText("");

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.GONE);
                errorText.setVisibility(View.VISIBLE);
                break;
            }
            case NORMAL_ERROR: {
                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.VISIBLE);
                errorText.setVisibility(View.VISIBLE);
                animateError();
                break;
            }
            case RESET_ERROR: {
                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonResetPin.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                smartcardProgress.setVisibility(View.GONE);
                errorImage.setVisibility(View.VISIBLE);
                errorText.setVisibility(View.VISIBLE);
                animateError();
                break;
            }
        }
        currentState = newState;
    }

    private void animateError() {
        AnimatedVectorDrawableHelper.startAnimation(getActivity(), errorImage, R.drawable.hwsecurity_error);
    }

    @UiThread
    @Override
    public void onSecurityKeyDiscovered(@NonNull SecurityKey securityKey) {
        HwTimber.d("SecurityKeyDialogFragment -> onSecurityKeyDiscovered");

        switch (currentState) {
            case NORMAL_SMARTCARD:
            case NORMAL_SMARTCARD_HOLD: {
                gotoState(State.NORMAL_SMARTCARD_HOLD);

                try {
                    callback.onSecurityKeyDialogDiscovered(this, securityKey, staticPinProvider);
                } catch (IOException e) {
                    handleError(e);
                }
                break;
            }
            case RESET_SMARTCARD: {
                new Thread(() -> {
                    try {
                        updatePinUsingPuk(securityKey, resetPukSecret, resetNewPinSecret);

                        errorText.post(() -> errorText.setText(R.string.hwsecurity_ui_changed_pin));
                        innerBottomSheet.post(() -> gotoState(State.RESET_SUCCESS));
                        innerBottomSheet.postDelayed(() -> {
                            if (!isAdded()) {
                                return;
                            }
                            gotoState(State.NORMAL_ENTER_PIN);
                        }, TIME_DELAYED_STATE_CHANGE);
                    } catch (IOException e) {
                        innerBottomSheet.post(() -> handleError(e));
                    }
                }).start();
                break;
            }
            default:
                // do nothing
        }
    }

    @UiThread
    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
        handleError(exception);
    }

    @Override
    public void onSecurityKeyDisconnected(@NonNull SecurityKey securityKey) {

    }

    @AnyThread
    @Override
    public void postError(IOException exception) {
        bottomSheet.post(() -> handleError(exception));
    }

    @UiThread
    @Override
    public void handleError(IOException exception) {
        HwTimber.d(exception);

        switch (currentState) {
            case NORMAL_SMARTCARD:
            case NORMAL_SMARTCARD_HOLD: {
                try {
                    throw exception;
                } catch (OpenPgpCardBlockedException e) {
                    errorText.setText(R.string.hwsecurity_ui_error_no_pin_tries);
                    gotoState(State.NORMAL_ERROR);
                } catch (OpenPgpWrongPinException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_pin), State.NORMAL_ERROR, State.NORMAL_ENTER_PIN);
                } catch (OpenPgpPinTooShortException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_too_short_pin), State.NORMAL_ERROR, State.NORMAL_ENTER_PIN);
                } catch (OpenPgpPublicKeyUnavailableException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_no_pubkey), State.NORMAL_ERROR, State.NORMAL_SMARTCARD);
                } catch (SecurityKeyException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.NORMAL_ERROR, State.NORMAL_SMARTCARD);
                } catch (TagLostException e) {
//				gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_error_lost_tag), State.NORMAL_ERROR, State.NORMAL_SMARTCARD);
                } catch (IOException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.NORMAL_ERROR, State.NORMAL_SMARTCARD);
                }
                break;
            }
            case RESET_SMARTCARD: {
                try {
                    throw exception;
                } catch (OpenPgpCardBlockedException e) {
                    errorText.setText(R.string.hwsecurity_ui_error_no_puk_tries);
                    gotoState(State.RESET_ERROR);
                } catch (OpenPgpWrongPinException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_puk), State.RESET_ERROR, State.RESET_ENTER_PUK);
                } catch (OpenPgpPinTooShortException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_puk), State.RESET_ERROR, State.RESET_ENTER_PUK);
                } catch (SecurityKeyException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.RESET_ERROR, State.RESET_SMARTCARD);
                } catch (TagLostException e) {
//				gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_error_lost_tag), State.RESET_ERROR, State.RESET_SMARTCARD);
                } catch (IOException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.RESET_ERROR, State.RESET_SMARTCARD);
                }
                break;
            }
            default:
                HwTimber.d("handleError called in State other than NORMAL_SMARTCARD, NORMAL_SMARTCARD_HOLD or RESET_SMARTCARD.");
        }
    }

    private void gotoErrorStateAndDelayedState(String text, State errorState, State delayedState) {
        errorText.setText(text);
        gotoState(errorState);
        bottomSheet.postDelayed(() -> {
            if (!isAdded()) {
                return;
            }
            gotoState(delayedState);
        }, TIME_DELAYED_STATE_CHANGE);
    }

}
