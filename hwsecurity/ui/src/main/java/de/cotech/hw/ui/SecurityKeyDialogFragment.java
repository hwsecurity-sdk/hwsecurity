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
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.*;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.UiThread;
import androidx.appcompat.app.AppCompatDelegate;
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

import java.io.IOException;
import java.util.Objects;

import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyCallback;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.exceptions.SecurityKeyLostException;
import de.cotech.hw.openpgp.exceptions.OpenPgpLockedException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPinTooShortException;
import de.cotech.hw.openpgp.exceptions.OpenPgpPublicKeyUnavailableException;
import de.cotech.hw.openpgp.exceptions.OpenPgpWrongPinException;
import de.cotech.hw.openpgp.secrets.ByteSecretGenerator;
import de.cotech.hw.piv.exceptions.PivWrongPinException;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.StaticPinProvider;
import de.cotech.hw.ui.internal.*;
import de.cotech.hw.util.HwTimber;

/**
 * This dialog shows helpful animations and handles all the PIN/PUK input for you.
 * It still allows you full control over the operations you can execute on the Security Key.
 * <p>
 * Use the SecurityKeyDialogFactory to instantiate this.
 */
public abstract class SecurityKeyDialogFragment<T extends SecurityKey> extends BottomSheetDialogFragment
        implements SecurityKeyCallback<T>, PinInput.PinInputCallback, SecurityKeyDialogInterface {
    @SuppressWarnings("WeakerAccess") // public API
    public static final String FRAGMENT_TAG = "security-key-dialog-fragment";
    public static final String ARG_DIALOG_OPTIONS = "de.cotech.hw.ui.ARG_DIALOG_OPTIONS";

    private static final long TIME_DELAYED_STATE_CHANGE = 3000;

    private static final int SETUP_DEFAULT_PIN_LENGTH = 6;
    private static final int SETUP_DEFAULT_PUK_LENGTH = 8;

    static {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
    }

    private SecurityKeyDialogOptions options;

    private SecurityKeyDialogInterface.SecurityKeyDialogCallback callback;

    private KeyboardPreference keyboardPreference;

    private CoordinatorLayout coordinator;
    private FrameLayout bottomSheet;
    private ConstraintLayout innerBottomSheet;
    private TextView textViewTitle;
    private TextView textViewDescription;

    private MaterialButton buttonNegative;
    private MaterialButton buttonPositive;
    private MaterialButton buttonKeyboardSwitch;

    private StaticPinProvider staticPinProvider;

    private ByteSecret resetNewPinSecret;
    private ByteSecret resetPukSecret;
    private ByteSecret setupPinSecret;

    private SecurityKeyFormFactor securityKeyFormFactor;
    private SmartcardFormFactor smartcardFormFactor;

    private KeypadPinInput keypadPinInput;
    private KeyboardPinInput keyboardPinInput;

    private PinInput currentPinInput;

    private Guideline guidelineForceHeight;

    private ProgressView progressView;
    private ErrorView errorView;

    private View includeShowPuk;
    private WipeConfirmView wipeConfirmView;
    private TextView textPuk;
    private CheckBox checkboxPuk;

    private enum State {
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

    private State currentState;

    abstract public void initSecurityKeyConnectionMode(Bundle arguments);

    abstract public void updateSecurityKeyPinUsingPuk(SecurityKey securityKey, ByteSecret puk, ByteSecret newPin) throws IOException;

    abstract public boolean isSecurityKeyEmpty(SecurityKey securityKey) throws IOException;

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

        initSecurityKeyConnectionMode(arguments);

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

        keyboardPreference = new KeyboardPreference(context);
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
        buttonNegative = view.findViewById(R.id.buttonNegative);
        buttonPositive = view.findViewById(R.id.buttonPositive);
        buttonKeyboardSwitch = view.findViewById(R.id.buttonKeyboardSwitch);

        textViewTitle = view.findViewById(R.id.textTitle);
        textViewDescription = view.findViewById(R.id.textDescription);
        guidelineForceHeight = view.findViewById(R.id.guidelineForceHeight);
        includeShowPuk = view.findViewById(R.id.includeShowPuk);
        textPuk = view.findViewById(R.id.textPuk);
        checkboxPuk = view.findViewById(R.id.checkBoxPuk);
        checkboxPuk.setOnCheckedChangeListener((buttonView, isChecked) -> gotoState(State.NORMAL_SECURITY_KEY));

        buttonNegative.setOnClickListener(v -> cancel());
        buttonPositive.setOnClickListener(v -> gotoState(State.RESET_PIN_ENTER_PUK));
        buttonKeyboardSwitch.setOnClickListener(v -> showHidePinInput(!keyboardPreference.isKeyboardPreferred()));

        wipeConfirmView = new WipeConfirmView(view.findViewById(R.id.includeConfirmWipe));

        progressView = new ProgressView(view.findViewById(R.id.includeProgress));
        errorView = new ErrorView(view.findViewById(R.id.includeError));

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
                gotoState(State.NORMAL_SECURITY_KEY);
                break;
            }
            case RESET_PIN: {
                gotoState(State.RESET_PIN_ENTER_PUK);
                break;
            }
            case SETUP: {
                gotoState(State.SETUP_CHOOSE_PIN);
                break;
            }
            default: {
                throw new IllegalArgumentException("unknown PinMode!");
            }
        }
    }

    private void showHidePinInput(boolean showKeyboard) {
        if (showKeyboard) {
            currentPinInput = keyboardPinInput;

            keyboardPinInput.setVisibility(View.VISIBLE);
            keypadPinInput.setVisibility(View.GONE);
            buttonKeyboardSwitch.setIcon(getResources().getDrawable(R.drawable.hwsecurity_ic_keyboard_numeric));
            keyboardPinInput.openKeyboard();
            keyboardPreference.setIsKeyboardPreferred(true);
        } else {
            currentPinInput = keypadPinInput;

            keyboardPinInput.setVisibility(View.GONE);
            keypadPinInput.setVisibility(View.VISIBLE);
            buttonKeyboardSwitch.setIcon(getResources().getDrawable(R.drawable.hwsecurity_ic_keyboard_alphabetical));
            keyboardPreference.setIsKeyboardPreferred(false);
        }
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
                gotoState(State.NORMAL_SECURITY_KEY);
                break;
            }
            case RESET_PIN_ENTER_PUK: {
                resetPukSecret = pinSecret;
                gotoState(State.RESET_PIN_ENTER_NEW_PIN);
                break;
            }
            case RESET_PIN_ENTER_NEW_PIN: {
                resetNewPinSecret = pinSecret;
                gotoState(State.RESET_PIN_SECURITY_KEY);
                break;
            }
            case SETUP_CHOOSE_PIN: {
                setupPinSecret = pinSecret;
                gotoState(State.SETUP_SHOW_PUK);
                break;
            }
            default: {
                // do nothing
                break;
            }
        }
    }

    private void gotoState(State newState) {
        gotoState(newState, true);
    }

    private String getTitle() {
        if (options.getTitle() != null) {
            return options.getTitle();
        }
        switch (options.getPinMode()) {
            case PIN_INPUT: {
                return getString(R.string.hwsecurity_ui_title_login);
            }
            case NO_PIN_INPUT: {
                return getString(R.string.hwsecurity_ui_title_add);
            }
            case RESET_PIN: {
                return getString(R.string.hwsecurity_ui_title_reset_pin);
            }
            case SETUP: {
                return getString(R.string.hwsecurity_ui_title_setup);
            }
            default: {
                throw new IllegalArgumentException("unknown PinMode!");
            }
        }
    }

    private void gotoState(State newState, boolean isTransportNfc) {
        switch (newState) {
            case NORMAL_ENTER_PIN: {
                keypadPinInput.reset(options.getPinLength());

                textViewTitle.setText(getTitle());
                textViewDescription.setText(R.string.hwsecurity_ui_description_enter_pin);

                showHidePinInput(keyboardPreference.isKeyboardPreferred());
                buttonKeyboardSwitch.setVisibility(options.getAllowKeyboard() ? View.VISIBLE : View.GONE);
                buttonPositive.setText(R.string.hwsecurity_ui_button_reset);
                buttonPositive.setVisibility(options.getShowReset() ? View.VISIBLE : View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case NORMAL_SECURITY_KEY: {
                SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();
                keypadPinInput.reset(options.getPinLength());

                textViewTitle.setText(getTitle());
                textViewDescription.setText(R.string.hwsecurity_ui_description_start);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                boolean isSmartcardFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SMART_CARD;
                boolean isSecurityKeyFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SECURITY_KEY;
                smartcardFormFactor.setVisibility(isSmartcardFormFactor ? View.VISIBLE : View.GONE);
                securityKeyFormFactor.setVisibility(isSecurityKeyFormFactor ? View.VISIBLE : View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case NORMAL_SECURITY_KEY_HOLD: {
                textViewTitle.setText(getTitle());
                textViewDescription.setText(isTransportNfc ? R.string.hwsecurity_ui_description_hold_nfc : R.string.hwsecurity_ui_description_hold_usb);

                // no animation for speed!
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.VISIBLE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case RESET_PIN_ENTER_PUK: {
                keypadPinInput.reset(options.getPukLength());

                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText(R.string.hwsecurity_ui_description_enter_puk);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.VISIBLE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case RESET_PIN_ENTER_NEW_PIN: {
                keypadPinInput.reset(options.getPinLength());

                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText(R.string.hwsecurity_ui_description_enter_new_pin);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.VISIBLE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case RESET_PIN_SECURITY_KEY: {
                SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();

                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText(R.string.hwsecurity_ui_description_hold_nfc);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                boolean isSmartcardFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SMART_CARD;
                boolean isSecurityKeyFormFactor = options.getFormFactor() == SecurityKeyDialogOptions.FormFactor.SECURITY_KEY;
                smartcardFormFactor.setVisibility(isSmartcardFormFactor ? View.VISIBLE : View.GONE);
                securityKeyFormFactor.setVisibility(isSecurityKeyFormFactor ? View.VISIBLE : View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case RESET_PIN_SUCCESS: {
                textViewTitle.setText(R.string.hwsecurity_ui_title_reset_pin);
                textViewDescription.setText("");

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case NORMAL_ERROR: {
                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.VISIBLE);
                break;
            }
            case RESET_PIN_ERROR: {
                TransitionManager.beginDelayedTransition(innerBottomSheet);
                keypadPinInput.setVisibility(View.GONE);
                keyboardPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.VISIBLE);
                break;
            }
            case SETUP_CHOOSE_PIN: {
                int pinLength = options.getPinLength() == null ? SETUP_DEFAULT_PIN_LENGTH : options.getPinLength();
                keypadPinInput.reset(pinLength);

                textViewTitle.setText(getTitle());
                textViewDescription.setText(R.string.hwsecurity_ui_description_choose_pin);

                keyboardPinInput.setVisibility(View.GONE);
                keypadPinInput.setVisibility(View.VISIBLE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case SETUP_SHOW_PUK: {
                int pukLength = options.getPukLength() == null ? SETUP_DEFAULT_PUK_LENGTH : options.getPukLength();
                ByteSecret setupPuk = ByteSecretGenerator.getInstance().createRandomNumeric(pukLength);
                staticPinProvider = StaticPinProvider.getInstance(setupPinSecret, setupPuk);

                setupPuk.displayOnTextView(textPuk);

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                textViewTitle.setText(getTitle());
                textViewDescription.setText(R.string.hwsecurity_ui_description_puk);
                keyboardPinInput.setVisibility(View.GONE);
                keypadPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.VISIBLE);
                wipeConfirmView.setVisibility(View.GONE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
            case SETUP_CONFIRM_WIPE: {

                TransitionManager.beginDelayedTransition(innerBottomSheet);
                textViewTitle.setText(getTitle());
                textViewDescription.setText("");
                keyboardPinInput.setVisibility(View.GONE);
                keypadPinInput.setVisibility(View.GONE);
                buttonKeyboardSwitch.setVisibility(View.GONE);
                buttonPositive.setVisibility(View.GONE);
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.GONE);
                includeShowPuk.setVisibility(View.GONE);
                wipeConfirmView.setVisibility(View.VISIBLE);
                progressView.setVisibility(View.GONE);
                errorView.setVisibility(View.GONE);
                break;
            }
        }
        currentState = newState;
    }

    @UiThread
    @Override
    public void onSecurityKeyDiscovered(@NonNull SecurityKey securityKey) {
        HwTimber.d("SecurityKeyDialogFragment -> onSecurityKeyDiscovered");

        switch (currentState) {
            case NORMAL_ENTER_PIN: {
                // automatically proceed with PIN on NFC connection
                if (!securityKey.isTransportNfc()) {
                    break;
                }
                staticPinProvider = StaticPinProvider.getInstance(currentPinInput.getPin());
                // fall-through
            }
            case SETUP_CONFIRM_WIPE:
                // fall-through
            case NORMAL_SECURITY_KEY:
                // fall-through
            case NORMAL_SECURITY_KEY_HOLD: {
                gotoState(State.NORMAL_SECURITY_KEY_HOLD, securityKey.isTransportNfc());

                boolean isSetupMode = options.getPinMode() == SecurityKeyDialogOptions.PinMode.SETUP;
                boolean isWipedConfirmed = wipeConfirmView.isWipeConfirmed();
                if (isSetupMode && !isWipedConfirmed) {
                    try {
                        if (!isSecurityKeyEmpty(securityKey)) {
                            gotoState(State.SETUP_CONFIRM_WIPE);
                            return;
                        }
                    } catch (IOException e) {
                        handleError(e);
                        return;
                    }
                }

                try {
                    callback.onSecurityKeyDialogDiscovered(this, securityKey, staticPinProvider);
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

                        innerBottomSheet.post(() -> Toast.makeText(getContext(), R.string.hwsecurity_ui_changed_pin, Toast.LENGTH_LONG).show());
                        innerBottomSheet.post(() -> gotoState(State.RESET_PIN_SUCCESS));
                        innerBottomSheet.postDelayed(() -> {
                            if (!isAdded()) {
                                return;
                            }
                            if (options.getPinMode() == SecurityKeyDialogOptions.PinMode.RESET_PIN) {
                                dismiss();
                            } else {
                                gotoState(State.NORMAL_ENTER_PIN);
                            }
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
    public void postProgressMessage(String message) {
        bottomSheet.post(() -> handleProgressMessage(message));
    }

    @AnyThread
    @Override
    public void postError(IOException exception) {
        bottomSheet.post(() -> handleError(exception));
    }

    private void handleProgressMessage(String message) {
        progressView.setText(message);
    }

    @UiThread
    @Override
    public void handleError(IOException exception) {
        HwTimber.d(exception);

        switch (currentState) {
            case NORMAL_SECURITY_KEY:
            case NORMAL_SECURITY_KEY_HOLD: {
                try {
                    throw exception;
                } catch (OpenPgpLockedException e) {
                    errorView.setText(R.string.hwsecurity_ui_error_no_pin_tries);
                    gotoState(State.NORMAL_ERROR);
                } catch (OpenPgpWrongPinException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_pin, e.getPinRetriesLeft()), State.NORMAL_ERROR, State.NORMAL_ENTER_PIN);
                } catch (PivWrongPinException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_pin, e.getRetriesLeft()), State.NORMAL_ERROR, State.NORMAL_ENTER_PIN);
                } catch (OpenPgpPinTooShortException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_too_short_pin), State.NORMAL_ERROR, State.NORMAL_ENTER_PIN);
                } catch (OpenPgpPublicKeyUnavailableException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_no_pubkey), State.NORMAL_ERROR, State.NORMAL_SECURITY_KEY);
                } catch (SecurityKeyException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.NORMAL_ERROR, State.NORMAL_SECURITY_KEY);
                } catch (SecurityKeyLostException e) {
                    gotoState(State.NORMAL_SECURITY_KEY);
                } catch (IOException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.NORMAL_ERROR, State.NORMAL_SECURITY_KEY);
                }
                break;
            }
            case RESET_PIN_SECURITY_KEY: {
                try {
                    throw exception;
                } catch (OpenPgpLockedException e) {
                    errorView.setText(R.string.hwsecurity_ui_error_no_puk_tries);
                    gotoState(State.RESET_PIN_ERROR);
                } catch (OpenPgpWrongPinException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_puk, e.getPukRetriesLeft()), State.RESET_PIN_ERROR, State.RESET_PIN_ENTER_PUK);
                } catch (PivWrongPinException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_wrong_puk, e.getRetriesLeft()), State.RESET_PIN_ERROR, State.RESET_PIN_ENTER_PUK);
                } catch (OpenPgpPinTooShortException e) {
                    gotoErrorStateAndDelayedState(getString(R.string.hwsecurity_ui_error_too_short_puk), State.RESET_PIN_ERROR, State.RESET_PIN_ENTER_PUK);
                } catch (SecurityKeyException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.RESET_PIN_ERROR, State.RESET_PIN_SECURITY_KEY);
                } catch (SecurityKeyLostException e) {
                    // TODO
                } catch (IOException e) {
                    gotoErrorStateAndDelayedState(exception.getMessage(), State.RESET_PIN_ERROR, State.RESET_PIN_SECURITY_KEY);
                }
                break;
            }
            default:
                HwTimber.d("handleError called in State other than NORMAL_SECURITY_KEY, NORMAL_SECURITY_KEY_HOLD or RESET_PIN_SECURITY_KEY.");
        }
    }

    private void gotoErrorStateAndDelayedState(String text, State errorState, State delayedState) {
        errorView.setText(text);
        gotoState(errorState);
        bottomSheet.postDelayed(() -> {
            if (!isAdded()) {
                return;
            }
            gotoState(delayedState);
        }, TIME_DELAYED_STATE_CHANGE);
    }

}
