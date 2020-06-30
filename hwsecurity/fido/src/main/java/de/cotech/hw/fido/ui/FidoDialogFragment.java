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

package de.cotech.hw.fido.ui;


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
import de.cotech.hw.fido.FidoAuthenticateCallback;
import de.cotech.hw.fido.FidoAuthenticateRequest;
import de.cotech.hw.fido.FidoAuthenticateResponse;
import de.cotech.hw.fido.FidoRegisterCallback;
import de.cotech.hw.fido.FidoRegisterRequest;
import de.cotech.hw.fido.FidoRegisterResponse;
import de.cotech.hw.fido.FidoSecurityKey;
import de.cotech.hw.fido.FidoSecurityKeyConnectionMode;
import de.cotech.hw.ui.R;
import de.cotech.hw.fido.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.ui.internal.ErrorView;
import de.cotech.hw.ui.internal.NfcFullscreenView;
import de.cotech.hw.ui.internal.SecurityKeyFormFactor;
import de.cotech.hw.ui.internal.SmartcardFormFactor;
import de.cotech.hw.util.HwTimber;


public class FidoDialogFragment extends BottomSheetDialogFragment implements SecurityKeyCallback<FidoSecurityKey>, SecurityKeyFormFactor.SelectTransportCallback {
    private static final String FRAGMENT_TAG = "hwsecurity-fido-fragment";
    private static final String ARG_FIDO_REGISTER_REQUEST = "ARG_FIDO_REGISTER_REQUEST";
    private static final String ARG_FIDO_AUTHENTICATE_REQUEST = "ARG_FIDO_AUTHENTICATE_REQUEST";
    private static final String ARG_FIDO_OPTIONS = "de.cotech.hw.fido.ARG_FIDO_OPTIONS";

    private static final long TIME_DELAYED_SCREEN_CHANGE = 3000;

    static {
        AppCompatDelegate.setCompatVectorFromResourcesEnabled(true);
    }

    private OnFidoRegisterCallback fidoRegisterCallback;
    private OnFidoAuthenticateCallback fidoAuthenticateCallback;

    private CoordinatorLayout coordinator;
    private FrameLayout bottomSheet;
    private ConstraintLayout innerBottomSheet;
    private Guideline guidelineForceHeight;

    private MaterialButton buttonLeft;
    private MaterialButton buttonRight;

    private TextView textTitle;
    private TextView textDescription;

    private SecurityKeyFormFactor securityKeyFormFactor;
    private SmartcardFormFactor smartcardFormFactor;

    private ErrorView errorView;

    private FidoDialogOptions options;
    private FidoRegisterRequest fidoRegisterRequest;
    private FidoAuthenticateRequest fidoAuthenticateRequest;

    private NfcFullscreenView nfcFullscreenView;

    private enum Screen {
        START,
        NFC_FULLSCREEN,
        USB_INSERT,
        USB_PRESS_BUTTON,
        USB_SELECT_AND_PRESS_BUTTON,
        ERROR,
    }

    private Screen currentScreen;
    private Screen screenBeforeError;

    public void setFidoRegisterCallback(OnFidoRegisterCallback fidoRegisterCallback) {
        this.fidoRegisterCallback = fidoRegisterCallback;
    }

    public void setFidoAuthenticateCallback(OnFidoAuthenticateCallback fidoAuthenticateCallback) {
        this.fidoAuthenticateCallback = fidoAuthenticateCallback;
    }

    public interface OnFidoRegisterCallback {
        @UiThread
        void onFidoRegisterResponse(@NonNull FidoRegisterResponse fidoRegisterResponse);

        @UiThread
        default void onFidoRegisterCancel(@NonNull FidoRegisterRequest fidoRegisterRequest) {
        }

        @UiThread
        default void onFidoRegisterTimeout(@NonNull FidoRegisterRequest fidoRegisterRequest) {
        }
    }

    public interface OnFidoAuthenticateCallback {
        @UiThread
        void onFidoAuthenticateResponse(@NonNull FidoAuthenticateResponse fidoAuthenticateResponse);

        @UiThread
        default void onFidoAuthenticateCancel(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
        }

        @UiThread
        default void onFidoAuthenticateTimeout(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
        }
    }

    public static FidoDialogFragment newInstance(@NonNull FidoRegisterRequest fidoRegisterRequest, @NonNull FidoDialogOptions options) {
        Bundle args = new Bundle();
        args.putParcelable(ARG_FIDO_REGISTER_REQUEST, fidoRegisterRequest);
        args.putParcelable(ARG_FIDO_OPTIONS, options);

        FidoDialogFragment fragment = new FidoDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

    public static FidoDialogFragment newInstance(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest, @NonNull FidoDialogOptions options) {
        Bundle args = new Bundle();
        args.putParcelable(ARG_FIDO_AUTHENTICATE_REQUEST, fidoAuthenticateRequest);
        args.putParcelable(ARG_FIDO_OPTIONS, options);

        FidoDialogFragment fragment = new FidoDialogFragment();
        fragment.setArguments(args);
        return fragment;
    }

    public static FidoDialogFragment newInstance(@NonNull FidoRegisterRequest fidoRegisterRequest) {
        return newInstance(fidoRegisterRequest, FidoDialogOptions.builder().build());
    }

    public static FidoDialogFragment newInstance(@NonNull FidoAuthenticateRequest fidoAuthenticateRequest) {
        return newInstance(fidoAuthenticateRequest, FidoDialogOptions.builder().build());
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
        options = arguments.getParcelable(ARG_FIDO_OPTIONS);
        if (options == null) {
            throw new IllegalStateException("Do not create SecurityKeyDialogFragment directly, use static .newInstance() methods!");
        }

        setStyle(STYLE_NORMAL, options.getTheme());

        Context context = getContext();
        if (fidoRegisterCallback == null) {
            if (context instanceof OnFidoRegisterCallback) {
                setFidoRegisterCallback((OnFidoRegisterCallback) context);
            }
        }

        if (fidoAuthenticateCallback == null) {
            if (context instanceof OnFidoAuthenticateCallback) {
                setFidoAuthenticateCallback((OnFidoAuthenticateCallback) context);
            }
        }

        if (fidoRegisterCallback == null && fidoAuthenticateCallback == null) {
            if (savedInstanceState != null) {
                HwTimber.e("Dismissing FidoDialogFragment left without callbacks after configuration change!");
                dismiss();
                return;
            }
            throw new IllegalStateException("Activity must implement FidoDialogFragment.OnFidoAuthenticateCallback " +
                    "or FidoDialogFragment.OnFidoRegisterCallback!");
        }

        SecurityKeyManager.getInstance().registerCallback(new FidoSecurityKeyConnectionMode(), this, this);
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

    private void initTimeout(long timeoutSeconds) {
        final Handler handler = new Handler();
        handler.postDelayed(() -> {
            HwTimber.d("Timeout after %s seconds.", timeoutSeconds);

            errorView.setText(R.string.hwsecurity_fido_error_timeout);
            gotoScreen(Screen.ERROR);
            bottomSheet.postDelayed(() -> {
                if (!isAdded()) {
                    return;
                }
                dismissAllowingStateLoss();

                if (fidoAuthenticateRequest != null) {
                    fidoAuthenticateCallback.onFidoAuthenticateTimeout(fidoAuthenticateRequest);
                } else if (fidoRegisterRequest != null) {
                    fidoRegisterCallback.onFidoRegisterTimeout(fidoRegisterRequest);
                }
            }, TIME_DELAYED_SCREEN_CHANGE);
        }, timeoutSeconds * 1000);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Bundle arguments = getArguments();
        if (arguments == null) {
            throw new IllegalStateException("Do not create FidoDialogFragment directly, use static .newInstance() methods!");
        }
        fidoRegisterRequest = arguments.getParcelable(ARG_FIDO_REGISTER_REQUEST);
        fidoAuthenticateRequest = arguments.getParcelable(ARG_FIDO_AUTHENTICATE_REQUEST);

        if (fidoRegisterRequest != null && fidoRegisterCallback == null) {
            throw new IllegalStateException("Activity must implement OnFidoRegisterCallback to perform register " +
                    "operation with FidoDialogFragment!");
        }
        if (fidoAuthenticateRequest != null && fidoAuthenticateCallback == null) {
            throw new IllegalStateException("Activity must implement OnFidoRegisterCallback to perform register " +
                    "operation with FidoDialogFragment!");
        }

        if (options.getPreventScreenshots()) {
            // prevent screenshots
            getDialog().getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }

        if (options.getTimeoutSeconds() != null) {
            initTimeout(options.getTimeoutSeconds());
        }

        innerBottomSheet = view.findViewById(R.id.hwSecurityDialogBottomSheet);
        guidelineForceHeight = view.findViewById(R.id.guidelineForceHeight);
        buttonLeft = view.findViewById(R.id.buttonLeft);
        buttonRight = view.findViewById(R.id.buttonRight);
        textTitle = view.findViewById(R.id.textTitle);
        textDescription = view.findViewById(R.id.textDescription);

        smartcardFormFactor = new SmartcardFormFactor(view.findViewById(R.id.includeSmartcardFormFactor), this);
        securityKeyFormFactor = new SecurityKeyFormFactor(view.findViewById(R.id.includeSecurityKeyFormFactor), this, this, innerBottomSheet, options.getShowSdkLogo());

        errorView = new ErrorView(view.findViewById(de.cotech.hw.ui.R.id.includeError));

        nfcFullscreenView = new NfcFullscreenView(view.findViewById(de.cotech.hw.ui.R.id.includeNfcFullscreen), innerBottomSheet);

        buttonRight.setVisibility(View.INVISIBLE);
        buttonLeft.setOnClickListener(v -> getDialog().cancel());

        gotoScreen(Screen.START);
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        if (fidoAuthenticateRequest != null) {
            fidoAuthenticateCallback.onFidoAuthenticateCancel(fidoAuthenticateRequest);
        } else if (fidoRegisterRequest != null) {
            fidoRegisterCallback.onFidoRegisterCancel(fidoRegisterRequest);
        }
    }

    private String getStartTitle() {
        if (options.getTitle() != null) {
            return options.getTitle();
        } else if (fidoRegisterRequest != null) {
            return getResources().getString(R.string.hwsecurity_fido_title_default_register);
        } else {
            return getResources().getString(R.string.hwsecurity_fido_title_default_authenticate);
        }
    }

    private void gotoScreen(Screen newScreen) {
        switch (newScreen) {
            case START: {
                animateStart();
                break;
            }
            case NFC_FULLSCREEN: {
                securityKeyFormFactor.animateSelectNfc();
                break;
            }
            case USB_INSERT: {
                securityKeyFormFactor.animateSelectUsb();
                break;
            }
            case USB_PRESS_BUTTON: {
                securityKeyFormFactor.animateUsbPressButton();
                break;
            }
            case USB_SELECT_AND_PRESS_BUTTON: {
                securityKeyFormFactor.animateSelectUsbAndPressButton();
                break;
            }
            case ERROR: {
                animateError();
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
        smartcardFormFactor.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);

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
        textDescription.setText(R.string.hwsecurity_ui_description_start);

        textTitle.setVisibility(View.VISIBLE);
        textDescription.setVisibility(View.VISIBLE);
        errorView.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.VISIBLE);

        securityKeyFormFactor.resetAnimation();
    }

    private void animateError() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        textTitle.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        securityKeyFormFactor.setVisibility(View.GONE);
        smartcardFormFactor.setVisibility(View.GONE);
        nfcFullscreenView.setVisibility(View.GONE);
        errorView.setVisibility(View.VISIBLE);
    }

    @UiThread
    @Override
    public void onSecurityKeyDiscovered(@NonNull FidoSecurityKey securityKey) {
        switch (currentScreen) {
            case START: {
                if (securityKey.isTransportUsb()) {
                    gotoScreen(Screen.USB_SELECT_AND_PRESS_BUTTON);
                }
                sendFidoCommand(securityKey);
                break;
            }
            case USB_INSERT: {
                if (securityKey.isTransportUsb()) {
                    gotoScreen(Screen.USB_PRESS_BUTTON);
                }
                sendFidoCommand(securityKey);
                break;
            }
            default: {
                HwTimber.d("onSecurityKeyDiscovered unhandled screen: %s", currentScreen.name());
            }
        }

    }

    private void sendFidoCommand(@NonNull FidoSecurityKey securityKey) {
        if (fidoRegisterRequest != null) {
            securityKey.registerAsync(fidoRegisterRequest,
                    new FidoRegisterCallback() {
                        @Override
                        public void onRegisterResponse(FidoRegisterResponse response) {
                            fidoRegisterCallback.onFidoRegisterResponse(response);
                            if (securityKey.isTransportNfc()) {
                                securityKey.release();
                            }
                            dismiss();
                        }

                        @Override
                        public void onIoException(IOException e) {
                            handleError(e);
                        }
                    }, this);
        }

        if (fidoAuthenticateRequest != null) {
            securityKey.authenticateAsync(fidoAuthenticateRequest,
                    new FidoAuthenticateCallback() {
                        @Override
                        public void onAuthenticateResponse(FidoAuthenticateResponse response) {
                            fidoAuthenticateCallback.onFidoAuthenticateResponse(response);
                            if (securityKey.isTransportNfc()) {
                                securityKey.release();
                            }
                            dismiss();
                        }

                        @Override
                        public void onIoException(IOException e) {
                            handleError(e);
                        }
                    }, this);
        }
    }

    @Override
    public void onSecurityKeyDisconnected(@NonNull FidoSecurityKey securityKey) {
        HwTimber.d("onSecurityKeyDisconnected");

        switch (currentScreen) {
            case USB_PRESS_BUTTON:
            case USB_SELECT_AND_PRESS_BUTTON:
                gotoScreen(Screen.START);
            default:
                HwTimber.d("onSecurityKeyDisconnected unhandled screen: %s", currentScreen.name());
        }
    }

    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
        handleError(exception);
    }

    private void handleError(IOException exception) {
        HwTimber.d(exception);

        if (currentScreen == Screen.ERROR) {
            // keep current screenBeforeError
        } else if (currentScreen == Screen.NFC_FULLSCREEN) {
//            screenBeforeError = Screen.NFC_SWEETSPOT;
        } else {
            screenBeforeError = Screen.START;
        }

        try {
            throw exception;
        } catch (FidoWrongKeyHandleException e) {
            showError(getString(R.string.hwsecurity_fido_error_wrong_security_key));
        } catch (SecurityKeyException e) {
            showError(getString(R.string.hwsecurity_fido_error_internal, e.getShortErrorName()));
        } catch (SecurityKeyDisconnectedException e) {
            // not handled
        } catch (IOException e) {
            showError(getString(R.string.hwsecurity_fido_error_internal, e.getMessage()));
        }
    }

    private void showError(String text) {
        errorView.setText(text);
        gotoScreen(Screen.ERROR);
        bottomSheet.postDelayed(() -> {
            if (!isAdded()) {
                return;
            }
            gotoScreen(screenBeforeError);
        }, TIME_DELAYED_SCREEN_CHANGE);
    }

}
