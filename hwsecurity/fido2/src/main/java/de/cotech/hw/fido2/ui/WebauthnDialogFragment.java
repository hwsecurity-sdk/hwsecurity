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


import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;

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

import de.cotech.hw.SecurityKeyCallback;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.exceptions.SecurityKeyDisconnectedException;
import de.cotech.hw.fido2.Fido2SecurityKey;
import de.cotech.hw.fido2.Fido2SecurityKeyConnectionMode;
import de.cotech.hw.fido2.Fido2SecurityKeyConnectionModeConfig;
import de.cotech.hw.fido2.PublicKeyCredential;
import de.cotech.hw.fido2.PublicKeyCredentialCreate;
import de.cotech.hw.fido2.PublicKeyCredentialGet;
import de.cotech.hw.ui.R;
import de.cotech.hw.fido2.WebauthnCallback;
import de.cotech.hw.fido2.domain.UserVerificationRequirement;
import de.cotech.hw.fido2.exceptions.FidoClientPinBlockedException;
import de.cotech.hw.fido2.exceptions.FidoClientPinInvalidException;
import de.cotech.hw.fido2.exceptions.FidoClientPinLastAttemptException;
import de.cotech.hw.fido2.exceptions.FidoClientPinNotSetException;
import de.cotech.hw.fido2.exceptions.FidoClientPinNotSupportedException;
import de.cotech.hw.fido2.exceptions.FidoClientPinRequiredException;
import de.cotech.hw.fido2.exceptions.FidoClientPinTooShortException;
import de.cotech.hw.fido2.exceptions.FidoInvalidCredentialException;
import de.cotech.hw.fido2.exceptions.FidoResidentKeyNoCredentialException;
import de.cotech.hw.fido2.internal.webauthn.WebauthnCommand;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.internal.ErrorView;
import de.cotech.hw.ui.internal.KeyboardPinInput;
import de.cotech.hw.ui.internal.KeyboardPreferenceRepository;
import de.cotech.hw.ui.internal.KeypadPinInput;
import de.cotech.hw.ui.internal.NfcFullscreenView;
import de.cotech.hw.ui.internal.PinInput;
import de.cotech.hw.ui.internal.SecurityKeyFormFactor;
import de.cotech.hw.ui.internal.SmartcardFormFactor;
import de.cotech.hw.util.HwTimber;


public class WebauthnDialogFragment extends BottomSheetDialogFragment
        implements SecurityKeyCallback<Fido2SecurityKey>, SecurityKeyFormFactor.SelectTransportCallback, PinInput.PinInputCallback {
    private static final String FRAGMENT_TAG = "hwsecurity-webauthn-fragment";
    private static final String ARG_WEBAUTHN_COMMAND = "ARG_WEBAUTHN_COMMAND";
    private static final String ARG_WEBAUTHN_OPTIONS = "de.cotech.hw.fido.ARG_WEBAUTHN_OPTIONS";

    private static final long TIME_DELAYED_SCREEN_CHANGE = 3000;

    static {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
    }

    private OnMakeCredentialCallback onMakeCredentialCallback;
    private OnGetAssertionCallback onGetAssertionCallback;

    private CoordinatorLayout coordinator;
    private FrameLayout bottomSheet;
    private ConstraintLayout innerBottomSheet;
    private Guideline guidelineForceHeight;

    private MaterialButton buttonLeft;
    private MaterialButton buttonRight;
    private MaterialButton buttonPinInputSwitch;

    private SecurityKeyFormFactor securityKeyFormFactor;
    private SmartcardFormFactor smartcardFormFactor;

    private KeypadPinInput keypadPinInput;
    private KeyboardPinInput keyboardPinInput;
    private PinInput currentPinInput;

    private TextView textTitle;
    private TextView textDescription;

    private ErrorView errorView;

    private WebauthnDialogOptions options;
    private WebauthnCommand webauthnCommand;

    private NfcFullscreenView nfcFullscreenView;
    private ByteSecret currentClientPin;

    private KeyboardPreferenceRepository keyboardPreferenceRepository;

    private enum Screen {
        START_SECURITY_KEY,
        START_ENTER_PIN,
        START_ENTER_PIN_SKIP,
        USB_INSERT,
        USB_PRESS_BUTTON,
        USB_SELECT_AND_PRESS_BUTTON,
        ERROR,
    }

    private Screen currentScreen;

    public void setOnMakeCredentialCallback(OnMakeCredentialCallback onMakeCredentialCallback) {
        this.onMakeCredentialCallback = onMakeCredentialCallback;
    }

    public void setOnGetAssertionCallback(OnGetAssertionCallback onGetAssertionCallback) {
        this.onGetAssertionCallback = onGetAssertionCallback;
    }

    public interface OnMakeCredentialCallback {
        @UiThread
        void onMakeCredentialResponse(@NonNull PublicKeyCredential publicKeyCredential);

        @UiThread
        default void onMakeCredentialCancel() {
        }

        @UiThread
        default void onMakeCredentialTimeout() {
        }
    }

    public interface OnGetAssertionCallback {
        @UiThread
        void onGetAssertionResponse(@NonNull PublicKeyCredential response);

        @UiThread
        default void onGetAssertionCancel() {
        }

        @UiThread
        default void onGetAssertionTimeout() {
        }
    }

    public static WebauthnDialogFragment newInstance(@NonNull WebauthnCommand webauthnCommand, @NonNull WebauthnDialogOptions options) {
        Bundle args = new Bundle();
        args.putParcelable(ARG_WEBAUTHN_COMMAND, webauthnCommand);
        args.putParcelable(ARG_WEBAUTHN_OPTIONS, options);

        WebauthnDialogFragment fragment = new WebauthnDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

    public static WebauthnDialogFragment newInstance(@NonNull WebauthnCommand webauthnCommand) {
        return newInstance(webauthnCommand, WebauthnDialogOptions.builder().build());
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
            throw new IllegalStateException("Do not create this dialog directly, use static .newInstance() methods!");
        }
        options = arguments.getParcelable(ARG_WEBAUTHN_OPTIONS);
        if (options == null) {
            throw new IllegalStateException("Do not create this dialog directly, use static .newInstance() methods!");
        }

        setStyle(STYLE_NORMAL, options.getTheme());

        Context context = getContext();
        if (onMakeCredentialCallback == null) {
            if (context instanceof OnMakeCredentialCallback) {
                setOnMakeCredentialCallback((OnMakeCredentialCallback) context);
            }
        }

        if (onGetAssertionCallback == null) {
            if (context instanceof OnGetAssertionCallback) {
                setOnGetAssertionCallback((OnGetAssertionCallback) context);
            }
        }

        if (onMakeCredentialCallback == null && onGetAssertionCallback == null) {
            if (savedInstanceState != null) {
                HwTimber.e("Dismissing WebAuthnDialogFragment left without callbacks after configuration change!");
                dismiss();
                return;
            }
            throw new IllegalStateException("Activity must implement WebAuthnDialogFragment.onMakeCredentialCallback " +
                    "or WebAuthnDialogFragment.onGetAssertionCallback!");
        }

        Fido2SecurityKeyConnectionModeConfig config = Fido2SecurityKeyConnectionModeConfig.builder()
                .setForceU2f(options.isForceU2f())
                .build();
        SecurityKeyManager.getInstance().registerCallback(
                Fido2SecurityKeyConnectionMode.getInstance(config), this, this);

        keyboardPreferenceRepository = new KeyboardPreferenceRepository(context);
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

    private void initTimeout(long timeoutMs) {
        final Handler handler = new Handler();
        handler.postDelayed(() -> {
            HwTimber.d("Timeout after %s milliseconds.", timeoutMs);

            errorView.setText(R.string.hwsecurity_fido_error_timeout);
            gotoScreen(Screen.ERROR);
            bottomSheet.postDelayed(() -> {
                if (!isAdded()) {
                    return;
                }
                dismissAllowingStateLoss();

                if (webauthnCommand instanceof PublicKeyCredentialCreate) {
                    onMakeCredentialCallback.onMakeCredentialTimeout();
                } else if (webauthnCommand instanceof PublicKeyCredentialGet) {
                    onGetAssertionCallback.onGetAssertionTimeout();
                }
            }, TIME_DELAYED_SCREEN_CHANGE);
        }, timeoutMs);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Bundle arguments = getArguments();
        if (arguments == null) {
            throw new IllegalStateException("Do not create this dialog directly, use static .newInstance() methods!");
        }
        webauthnCommand = arguments.getParcelable(ARG_WEBAUTHN_COMMAND);

        if (webauthnCommand instanceof PublicKeyCredentialCreate && onMakeCredentialCallback == null) {
            throw new IllegalStateException("Activity must implement onMakeCredentialCallback to perform makeCredential " +
                    "operation with WebAuthnDialogFragment!");
        }
        if (webauthnCommand instanceof PublicKeyCredentialGet && onGetAssertionCallback == null) {
            throw new IllegalStateException("Activity must implement onGetAssertionCallback to perform getAssertion " +
                    "operation with WebAuthnDialogFragment!");
        }

        if (options.getPreventScreenshots()) {
            // prevent screenshots
            getDialog().getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }

        if (options.getTimeoutMs() != null) {
            initTimeout(options.getTimeoutMs());
        }

        innerBottomSheet = view.findViewById(R.id.hwSecurityDialogBottomSheet);
        guidelineForceHeight = view.findViewById(R.id.guidelineForceHeight);
        buttonLeft = view.findViewById(R.id.buttonLeft);
        buttonRight = view.findViewById(R.id.buttonRight);
        buttonPinInputSwitch = view.findViewById(de.cotech.hw.ui.R.id.buttonKeyboardSwitch);
        buttonPinInputSwitch.setOnClickListener(v -> switchBetweenPinInputs());

        textTitle = view.findViewById(R.id.textTitle);
        textDescription = view.findViewById(R.id.textDescription);

        smartcardFormFactor = new SmartcardFormFactor(view.findViewById(R.id.includeSmartcardFormFactor), this);
        securityKeyFormFactor = new SecurityKeyFormFactor(view.findViewById(R.id.includeSecurityKeyFormFactor), this, this, innerBottomSheet, options.getShowSdkLogo());

        errorView = new ErrorView(view.findViewById(de.cotech.hw.ui.R.id.includeError));

        nfcFullscreenView = new NfcFullscreenView(view.findViewById(de.cotech.hw.ui.R.id.includeNfcFullscreen), innerBottomSheet);

        keypadPinInput = new KeypadPinInput(view.findViewById(de.cotech.hw.ui.R.id.includeKeypadInput));
        keypadPinInput.reset(null);
        keypadPinInput.setPinInputCallback(this);

        keyboardPinInput = new KeyboardPinInput(view.findViewById(de.cotech.hw.ui.R.id.includeKeyboardInput));
        keyboardPinInput.setPinInputCallback(this);

        buttonLeft.setOnClickListener(v -> getDialog().cancel());

        gotoScreenOnCreate();
    }

    public void switchBetweenPinInputs() {
        boolean isKeyboardPreferred = keyboardPreferenceRepository.isKeyboardPreferred();

        if (isKeyboardPreferred) {
            keyboardPreferenceRepository.setIsKeyboardPreferred(false);
            showKeypadPinInput();
        } else {
            keyboardPreferenceRepository.setIsKeyboardPreferred(true);
            showKeyboardPinInput();
        }
    }

    private void showKeyboardPinInput() {
        currentPinInput = keyboardPinInput;

        keyboardPinInput.setVisibility(View.VISIBLE);
        keypadPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setIcon(getResources().getDrawable(de.cotech.hw.ui.R.drawable.hwsecurity_ic_keyboard_numeric));
        keyboardPinInput.openKeyboard();
    }

    private void showKeypadPinInput() {
        currentPinInput = keypadPinInput;

        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.VISIBLE);
        buttonPinInputSwitch.setIcon(getResources().getDrawable(de.cotech.hw.ui.R.drawable.hwsecurity_ic_keyboard_alphabetical));
    }

    @Override
    public void onPinEntered(ByteSecret pinSecret) {
        if (pinSecret == null) {
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_pin_required),
                    Screen.ERROR, Screen.START_ENTER_PIN);
            return;
        }

        currentClientPin = pinSecret;
        switch (currentScreen) {
            case START_ENTER_PIN_SKIP:
            case START_ENTER_PIN: {
                gotoScreen(Screen.START_SECURITY_KEY);
                break;
            }
            default: {
                // do nothing
                break;
            }
        }
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        if (webauthnCommand instanceof PublicKeyCredentialCreate) {
            onMakeCredentialCallback.onMakeCredentialCancel();
        } else if (webauthnCommand instanceof PublicKeyCredentialGet) {
            onGetAssertionCallback.onGetAssertionCancel();
        }
    }

    private String getStartTitle() {
        if (options.getTitle() != null) {
            return options.getTitle();
        } else if (webauthnCommand instanceof PublicKeyCredentialCreate) {
            return getResources().getString(R.string.hwsecurity_fido_title_default_register);
        } else if (webauthnCommand instanceof PublicKeyCredentialGet) {
            return getResources().getString(R.string.hwsecurity_fido_title_default_authenticate);
        } else {
            return "";
        }
    }

    private void gotoScreenOnCreate() {
        UserVerificationRequirement uvr;
        if (webauthnCommand instanceof PublicKeyCredentialGet) {
            uvr = ((PublicKeyCredentialGet) webauthnCommand).options().userVerification();
        } else if (webauthnCommand instanceof PublicKeyCredentialCreate) {
            uvr = ((PublicKeyCredentialCreate) webauthnCommand).options().authenticatorSelection().userVerification();
        } else {
            throw new IllegalStateException("Expected either PublicKeyCredentialGet or PublicKeyCredentialCreate command type!");
        }

        //  - if explicitly required, ask for pin and don't allow skipping
        //  - if preferred, ask for pin but allow "Skip"
        //  - if discouraged (i.e. otherwise), don't ask for pin
        if (uvr == UserVerificationRequirement.REQUIRED) {
            gotoScreen(Screen.START_ENTER_PIN);
        } else if (uvr == UserVerificationRequirement.PREFERRED) {
            gotoScreen(Screen.START_ENTER_PIN_SKIP);
        } else {
            gotoScreen(Screen.START_SECURITY_KEY);
        }
    }

    private void gotoScreen(Screen newScreen) {
        switch (newScreen) {
            case START_SECURITY_KEY: {
                animateStart();
                SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();
                break;
            }
            case START_ENTER_PIN: {
                showPinInput(false);
                break;
            }
            case START_ENTER_PIN_SKIP: {
                boolean allowSkipPin = options.getAllowSkipPin();
                showPinInput(allowSkipPin);
                break;
            }
            case USB_INSERT: {
                buttonPinInputSwitch.setVisibility(View.GONE);
                securityKeyFormFactor.animateSelectUsb();
                break;
            }
            case USB_PRESS_BUTTON: {
                buttonPinInputSwitch.setVisibility(View.GONE);
                securityKeyFormFactor.animateUsbPressButton();
                break;
            }
            case USB_SELECT_AND_PRESS_BUTTON: {
                buttonPinInputSwitch.setVisibility(View.GONE);
                securityKeyFormFactor.animateSelectUsbAndPressButton();
                break;
            }
            case ERROR: {
                showError();
                break;
            }
        }
        currentScreen = newScreen;
    }

    @Override
    public void screeFullscreenNfc() {
        textTitle.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        smartcardFormFactor.setVisibility(View.GONE);
        buttonRight.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.GONE);

        nfcFullscreenView.setVisibility(View.VISIBLE);
        nfcFullscreenView.animateNfcFullscreen(getDialog());
    }

    @Override
    public void onSecurityKeyFormFactorClickUsb() {
        currentScreen = Screen.USB_INSERT;
    }

    private void animateStart() {
        buttonLeft.setText(R.string.hwsecurity_ui_button_cancel);
        textTitle.setText(getStartTitle());
        switch (options.getFormFactor()) {
            case SMART_CARD: {
                textDescription.setText("");
                break;
            }
            case SECURITY_KEY: {
                textDescription.setText(R.string.hwsecurity_ui_description_start);
                break;
            }
        }

        buttonRight.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        textTitle.setVisibility(View.VISIBLE);
        textDescription.setVisibility(View.VISIBLE);
        errorView.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.GONE);
        switch (options.getFormFactor()) {
            case SMART_CARD: {
                smartcardFormFactor.setVisibility(View.VISIBLE);
                securityKeyFormFactor.setVisibility(View.GONE);
                break;
            }
            case SECURITY_KEY: {
                smartcardFormFactor.setVisibility(View.GONE);
                securityKeyFormFactor.setVisibility(View.VISIBLE);
                break;
            }
        }
    }

    public void showPinInput(boolean allowSkip) {
        buttonLeft.setText(R.string.hwsecurity_ui_button_cancel);
        textTitle.setText(getStartTitle());
        textDescription.setText(R.string.hwsecurity_ui_description_enter_pin);

        textTitle.setVisibility(View.VISIBLE);
        textDescription.setVisibility(View.VISIBLE);
        errorView.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        smartcardFormFactor.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(options.getAllowKeyboard() ? View.VISIBLE : View.INVISIBLE);

        if (allowSkip) {
            buttonRight.setText(R.string.hwsecurity_fido_button_pin_skip);
            buttonRight.setOnClickListener(view -> gotoScreen(Screen.START_SECURITY_KEY));
            buttonRight.setVisibility(View.VISIBLE);
        } else {
            buttonRight.setVisibility(View.INVISIBLE);
        }

        boolean isKeyboardPreferred = keyboardPreferenceRepository.isKeyboardPreferred();

        keypadPinInput.reset(null);
        if (isKeyboardPreferred) {
            showKeyboardPinInput();
        } else {
            showKeypadPinInput();
        }
    }

    private void showError() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        textTitle.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        smartcardFormFactor.setVisibility(View.GONE);
        nfcFullscreenView.setVisibility(View.GONE);
        errorView.setVisibility(View.VISIBLE);
        buttonRight.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
    }

    @SuppressLint("WrongThread")
    @UiThread
    @Override
    public void onSecurityKeyDiscovered(@NonNull Fido2SecurityKey securityKey) {
        switch (currentScreen) {
            case START_ENTER_PIN_SKIP:
                // fall-through
            case START_ENTER_PIN: {
                // Only stay in this screen for USB. Automatically proceed with entered PIN on NFC connection
                if (!securityKey.isTransportNfc()) {
                    break;
                }
                currentPinInput.confirmPin();
                // fall-through
            }
            case START_SECURITY_KEY: {
                if (securityKey.isTransportUsb()) {
                    gotoScreen(Screen.USB_SELECT_AND_PRESS_BUTTON);
                }
                sendWebAuthnCommands(securityKey);
                break;
            }
            case USB_INSERT: {
                if (securityKey.isTransportUsb()) {
                    gotoScreen(Screen.USB_PRESS_BUTTON);
                }
                sendWebAuthnCommands(securityKey);
                break;
            }
            default: {
                HwTimber.d("onSecurityKeyDiscovered unhandled screen: %s", currentScreen.name());
            }
        }
    }

    private void sendWebAuthnCommands(@NonNull Fido2SecurityKey securityKey) {
        if (currentClientPin != null) {
            String clientPin = new String(currentClientPin.getByteCopyAndClear());
            currentClientPin = null;

            // TODO: implement UI for last PIN attempt
            webauthnCommand = webauthnCommand.withClientPin(clientPin, true);
        }

        if (webauthnCommand instanceof PublicKeyCredentialCreate) {
            securityKey.webauthnCommandAsync(webauthnCommand,
                    new WebauthnCallback<PublicKeyCredential>() {
                        @Override
                        public void onResponse(PublicKeyCredential publicKeyCredential) {
                            onMakeCredentialCallback.onMakeCredentialResponse(publicKeyCredential);
                            if (securityKey.isTransportNfc()) {
                                securityKey.release();
                            }
                            dismiss();
                        }

                        @Override
                        public void onIoException(IOException e) {
                            handleErrorPublicKeyCredentialCreateError(e);
                        }
                    }, this);
        }

        if (webauthnCommand instanceof PublicKeyCredentialGet) {
            securityKey.webauthnCommandAsync(webauthnCommand,
                    new WebauthnCallback<PublicKeyCredential>() {
                        @Override
                        public void onResponse(PublicKeyCredential response) {
                            onGetAssertionCallback.onGetAssertionResponse(response);
                            if (securityKey.isTransportNfc()) {
                                securityKey.release();
                            }
                            dismiss();
                        }

                        @Override
                        public void onIoException(IOException e) {
                            handleErrorPublicKeyCredentialGet(e);
                        }
                    }, this);
        }
    }

    private void handleErrorPublicKeyCredentialGet(IOException exception) {
        try {
            throw exception;
        } catch (FidoClientPinNotSetException e) {
            errorView.setText(R.string.hwsecurity_fido_error_pin_not_set);
            gotoScreen(Screen.ERROR);
        } catch (FidoClientPinInvalidException e) {
            // if invalid pin was given
            // attempts left in ((FidoClientPinInvalidException) e).retriesLeft
            // if zero, key is now blocked
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_wrong_pin, e.getRetriesLeft()),
                    Screen.ERROR, Screen.START_ENTER_PIN);
        } catch (FidoClientPinLastAttemptException e) {
            // thrown if only one attempt left, but "lastAttemptOk" above was false.
            // "hold again to make attempt" or something?
            // alternatively, just set lastAttemptOk to true and don't bother :)
            // TODO
        } catch (FidoClientPinBlockedException e) {
            // fido key was already blocked, and must be reset
            errorView.setText(R.string.hwsecurity_fido_error_blocked);
            gotoScreen(Screen.ERROR);
        } catch (FidoClientPinNotSupportedException e) {
            // if UV was requested, but not supported by authenticator
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_pin_not_supported),
                    Screen.ERROR, Screen.START_ENTER_PIN_SKIP);
        } catch (FidoClientPinRequiredException e) {
            // if UV was requested, but no PIN provided (shouldn't happen)
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_pin_required),
                    Screen.ERROR, Screen.START_ENTER_PIN);
        } catch (FidoResidentKeyNoCredentialException e) {
            // if resident key was requested, but none stored for domain on FIDO key
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_wrong_security_key),
                    Screen.ERROR, Screen.START_ENTER_PIN_SKIP);
        } catch (FidoInvalidCredentialException e) {
            // if credential isn't valid (probably means wrong authenticator?)
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_wrong_security_key),
                    Screen.ERROR, Screen.START_ENTER_PIN_SKIP);
        } catch (FidoClientPinTooShortException e) {
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_pin_too_short),
                    Screen.ERROR, Screen.START_ENTER_PIN_SKIP);
        } catch (SecurityKeyException e) {
            errorView.setText(getString(R.string.hwsecurity_fido_error_internal, e.getShortErrorName()));
            gotoScreen(Screen.ERROR);
        } catch (SecurityKeyDisconnectedException e) {
            // do nothing if we loose connection
        } catch (IOException e) {
            errorView.setText(getString(R.string.hwsecurity_fido_error_internal, e.getMessage()));
            gotoScreen(Screen.ERROR);
        }
    }

    private void handleErrorPublicKeyCredentialCreateError(IOException exception) {
        try {
            throw exception;
        } catch (FidoClientPinNotSetException e) {
            errorView.setText(R.string.hwsecurity_fido_error_pin_not_set);
            gotoScreen(Screen.ERROR);
        } catch (FidoClientPinInvalidException e) {
            // if invalid pin was given
            // attempts left in ((FidoClientPinInvalidException) e).retriesLeft
            // if zero, key is now blocked
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_wrong_pin, e.getRetriesLeft()),
                    Screen.ERROR, Screen.START_ENTER_PIN);
        } catch (FidoClientPinLastAttemptException e) {
            // thrown if only one attempt left, but "lastAttemptOk" above was false.
            // "hold again to make attempt" or something?
            // alternatively, just set lastAttemptOk to true and don't bother :)
            // TODO
        } catch (FidoClientPinBlockedException e) {
            // fido key was already blocked, and must be reset
            errorView.setText(R.string.hwsecurity_fido_error_blocked);
            gotoScreen(Screen.ERROR);
        } catch (FidoClientPinRequiredException e) {
            // if authenticator has a PIN set, but none was given. once a PIN
            // is set, MakeCredential *always* requires it.
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_pin_required),
                    Screen.ERROR, Screen.START_ENTER_PIN);
        } catch (FidoClientPinTooShortException e) {
            gotoErrorScreenAndDelayedScreen(getString(R.string.hwsecurity_fido_error_pin_too_short),
                    Screen.ERROR, Screen.START_ENTER_PIN_SKIP);
        } catch (SecurityKeyException e) {
            errorView.setText(getString(R.string.hwsecurity_fido_error_internal, e.getShortErrorName()));
            gotoScreen(Screen.ERROR);
        } catch (SecurityKeyDisconnectedException e) {
            // do nothing if we loose connection
        } catch (IOException e) {
            errorView.setText(getString(R.string.hwsecurity_fido_error_internal, e.getMessage()));
            gotoScreen(Screen.ERROR);
        }
    }

    @Override
    public void onSecurityKeyDisconnected(@NonNull Fido2SecurityKey securityKey) {
        HwTimber.d("onSecurityKeyDisconnected");

        switch (currentScreen) {
            case USB_PRESS_BUTTON:
            case USB_SELECT_AND_PRESS_BUTTON:
                gotoScreen(Screen.START_SECURITY_KEY);
            default:
                HwTimber.d("onSecurityKeyDisconnected unhandled screen: %s", currentScreen.name());
        }
    }

    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
        handleErrorPublicKeyCredentialCreateError(exception);
    }

    private void gotoErrorScreenAndDelayedScreen(String text, Screen errorScreen, Screen delayedScreen) {
        errorView.setText(text);
        gotoScreen(errorScreen);
        bottomSheet.postDelayed(() -> {
            if (!isAdded()) {
                return;
            }
            gotoScreen(delayedScreen);
        }, TIME_DELAYED_SCREEN_CHANGE);
    }

}
