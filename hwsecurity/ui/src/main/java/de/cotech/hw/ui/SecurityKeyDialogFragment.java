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
import android.widget.CheckBox;
import android.widget.FrameLayout;
import android.widget.TextView;

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
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.PinProvider;
import de.cotech.hw.ui.internal.ErrorView;
import de.cotech.hw.ui.internal.KeyboardPinInput;
import de.cotech.hw.ui.internal.KeypadPinInput;
import de.cotech.hw.ui.internal.NfcFullscreenView;
import de.cotech.hw.ui.internal.PinInput;
import de.cotech.hw.ui.internal.ProgressView;
import de.cotech.hw.ui.internal.SecurityKeyDialogPresenter;
import de.cotech.hw.ui.internal.SecurityKeyFormFactor;
import de.cotech.hw.ui.internal.SmartcardFormFactor;
import de.cotech.hw.ui.internal.WipeConfirmView;
import de.cotech.hw.util.HwTimber;

/**
 * This dialog shows helpful animations and handles all the PIN/PUK input for you.
 * It still allows you full control over the operations you can execute on the Security Key.
 * <p>
 * Use the SecurityKeyDialogFactory to instantiate this.
 */
public abstract class SecurityKeyDialogFragment<T extends SecurityKey> extends BottomSheetDialogFragment
        implements SecurityKeyCallback<T>, PinInput.PinInputCallback, SecurityKeyDialogInterface, SecurityKeyDialogPresenter.View, SecurityKeyFormFactor.SelectTransportCallback {
    @SuppressWarnings("WeakerAccess") // public API
    public static final String FRAGMENT_TAG = "security-key-dialog-fragment";
    public static final String ARG_DIALOG_OPTIONS = "de.cotech.hw.ui.ARG_DIALOG_OPTIONS";

    static {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
    }

    private SecurityKeyDialogPresenter presenter;

    private SecurityKeyDialogOptions options;

    private SecurityKeyDialogInterface.SecurityKeyDialogCallback callback;

    private CoordinatorLayout coordinator;
    private FrameLayout bottomSheet;
    private ConstraintLayout innerBottomSheet;
    private TextView textTitle;
    private TextView textDescription;

    private MaterialButton buttonLeft;
    private MaterialButton buttonRight;
    private MaterialButton buttonPinInputSwitch;

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

    private NfcFullscreenView nfcFullscreenView;

    abstract public void initSecurityKeyConnectionMode(Bundle arguments);

    abstract public SecurityKeyDialogPresenter initPresenter(SecurityKeyDialogPresenter.View view, Context context, SecurityKeyDialogOptions options);

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

        presenter = initPresenter(this, getActivity(), options);
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
            Window window = Objects.requireNonNull(getDialog().getWindow());
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }

        innerBottomSheet = view.findViewById(R.id.hwSecurityDialogBottomSheet);
        buttonLeft = view.findViewById(R.id.buttonLeft);
        buttonRight = view.findViewById(R.id.buttonRight);
        buttonPinInputSwitch = view.findViewById(R.id.buttonKeyboardSwitch);

        textTitle = view.findViewById(R.id.textTitle);
        textDescription = view.findViewById(R.id.textDescription);
        guidelineForceHeight = view.findViewById(R.id.guidelineForceHeight);
        includeShowPuk = view.findViewById(R.id.includeShowPuk);
        textPuk = view.findViewById(R.id.textPuk);
        checkboxPuk = view.findViewById(R.id.checkBoxPuk);
        checkboxPuk.setOnCheckedChangeListener((buttonView, isChecked) -> presenter.finishedWithPuk());

        buttonLeft.setOnClickListener(v -> presenter.cancel());
        buttonRight.setOnClickListener(v -> presenter.resetPinScreen());
        buttonPinInputSwitch.setOnClickListener(v -> presenter.switchBetweenPinInputs());

        wipeConfirmView = new WipeConfirmView(view.findViewById(R.id.includeConfirmWipe));

        progressView = new ProgressView(view.findViewById(R.id.includeProgress));
        errorView = new ErrorView(view.findViewById(R.id.includeError));

        keypadPinInput = new KeypadPinInput(view.findViewById(R.id.includeKeypadInput));
        keypadPinInput.reset(options.getPinLength());
        keypadPinInput.setPinInputCallback(this);

        keyboardPinInput = new KeyboardPinInput(view.findViewById(R.id.includeKeyboardInput));
        keyboardPinInput.setPinInputCallback(this);

        smartcardFormFactor = new SmartcardFormFactor(view.findViewById(R.id.includeSmartcardFormFactor), this);
        securityKeyFormFactor = new SecurityKeyFormFactor(view.findViewById(R.id.includeSecurityKeyFormFactor), this, this, innerBottomSheet, options.getShowSdkLogo());

        nfcFullscreenView = new NfcFullscreenView(view.findViewById(R.id.includeNfcFullscreen), innerBottomSheet);

        presenter.gotoScreenOnCreate();
    }

    @Override
    public void showKeypadPinInput() {
        currentPinInput = keypadPinInput;

        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.VISIBLE);
        buttonPinInputSwitch.setIcon(getResources().getDrawable(R.drawable.hwsecurity_ic_keyboard_alphabetical));
    }

    @Override
    public void showKeyboardPinInput() {
        currentPinInput = keyboardPinInput;

        keyboardPinInput.setVisibility(View.VISIBLE);
        keypadPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setIcon(getResources().getDrawable(R.drawable.hwsecurity_ic_keyboard_numeric));
        keyboardPinInput.openKeyboard();
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
        presenter.onPinEntered(pinSecret);
    }

    public void updateTitle(String title, int descriptionResId) {
        updateTitle(title, getString(descriptionResId));
    }

    public void updateTitle(int titleResId, String description) {
        updateTitle(getString(titleResId), description);
    }

    public void updateTitle(int titleResId, int descriptionResId) {
        updateTitle(getString(titleResId), getString(descriptionResId));
    }

    public void updateTitle(String title, String description) {
        textTitle.setText(title);
        textDescription.setText(description);
    }

    @Override
    public void screenEnterPin(Integer pinLength, boolean showReset, boolean useKeyboard) {
        keypadPinInput.reset(pinLength);

        presenter.showPinInput();
        buttonPinInputSwitch.setVisibility(useKeyboard ? View.VISIBLE : View.GONE);
        buttonRight.setText(R.string.hwsecurity_ui_button_reset);
        buttonRight.setVisibility(showReset ? View.VISIBLE : View.GONE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenSecurityKey(Integer pinLength, SecurityKeyDialogOptions.FormFactor formFactor) {
        SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();
        keypadPinInput.reset(pinLength);

        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keypadPinInput.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        switch (formFactor) {
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
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenHoldSecurityKey() {
        // no animation for speed!
        keypadPinInput.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.VISIBLE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenResetPinEnterPinOrPuk(Integer pinOrPukLength) {
        keypadPinInput.reset(pinOrPukLength);

        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keypadPinInput.setVisibility(View.VISIBLE);
        keyboardPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenResetPinSecurityKey(SecurityKeyDialogOptions.FormFactor formFactor) {
        SecurityKeyManager.getInstance().rediscoverConnectedSecurityKeys();

        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keypadPinInput.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        switch (formFactor) {
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
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenResetPinSuccess() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keypadPinInput.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenError() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keypadPinInput.setVisibility(View.GONE);
        keyboardPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.VISIBLE);
    }

    @Override
    public void screenSetupChoosePin(int pinLength) {
        keypadPinInput.reset(pinLength);

        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.VISIBLE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenSetupChoosePuk(int pukLength, ByteSecret setupPuk) {
        setupPuk.displayOnTextView(textPuk);

        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.VISIBLE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screenConfirmWipe() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.VISIBLE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
    }

    @Override
    public void screeFullscreenNfc() {
        keyboardPinInput.setVisibility(View.GONE);
        keypadPinInput.setVisibility(View.GONE);
        buttonPinInputSwitch.setVisibility(View.GONE);
        buttonRight.setVisibility(View.INVISIBLE);
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        includeShowPuk.setVisibility(View.GONE);
        wipeConfirmView.setVisibility(View.GONE);
        progressView.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);

        textTitle.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);

        nfcFullscreenView.setVisibility(View.VISIBLE);
        nfcFullscreenView.animateNfcFullscreen(getDialog());
    }

    @Override
    public void onSecurityKeyFormFactorClickUsb() {

    }

    @UiThread
    @Override
    public void onSecurityKeyDiscovered(@NonNull SecurityKey securityKey) {
        HwTimber.d("SecurityKeyDialogFragment -> onSecurityKeyDiscovered");

        boolean isWipeConfirmed = wipeConfirmView.isWipeConfirmed();

        presenter.onSecurityKeyDiscovered(securityKey, isWipeConfirmed);
    }

    @Override
    public void onSecurityKeyDialogDiscoveredCallback(@NonNull SecurityKey securityKey, @Nullable PinProvider pinProvider) throws IOException {
        callback.onSecurityKeyDialogDiscovered(this, securityKey, pinProvider);
    }

    @Override
    public void updateErrorViewText(String text) {
        errorView.setText(text);
    }

    @Override
    public void updateErrorViewText(int text) {
        errorView.setText(text);
    }

    @Override
    public boolean postDelayedRunnable(Runnable action, long delayMillis) {
        return bottomSheet.postDelayed(() -> {
            if (!isAdded()) {
                return;
            }
            action.run();
        }, delayMillis);
    }

    @Override
    public boolean postRunnable(Runnable action) {
        return bottomSheet.post(action);
    }

    @UiThread
    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
        presenter.handleError(exception);
    }

    @Override
    public void onSecurityKeyDisconnected(@NonNull SecurityKey securityKey) {

    }

    @AnyThread
    @Override
    public void postProgressMessage(String message) {
        bottomSheet.post(() -> progressView.setText(message));
    }

    @AnyThread
    @Override
    public void postError(IOException exception) {
        bottomSheet.post(() -> presenter.handleError(exception));
    }

    @Override
    public void confirmPinInput() {
        currentPinInput.confirmPin();
    }
}
