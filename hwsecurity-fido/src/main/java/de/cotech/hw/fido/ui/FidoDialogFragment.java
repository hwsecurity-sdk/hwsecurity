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

package de.cotech.hw.fido.ui;


import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ArgbEvaluator;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.drawable.Drawable;
import android.nfc.TagLostException;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.provider.Settings;
import android.util.DisplayMetrics;
import android.util.Pair;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.UiThread;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.ViewCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.transition.AutoTransition;
import androidx.transition.Scene;
import androidx.transition.Transition;
import androidx.transition.TransitionManager;
import androidx.vectordrawable.graphics.drawable.Animatable2Compat;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import de.cotech.hw.SecurityKeyCallback;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.fido.FidoAuthenticateCallback;
import de.cotech.hw.fido.FidoAuthenticateRequest;
import de.cotech.hw.fido.FidoAuthenticateResponse;
import de.cotech.hw.fido.FidoRegisterCallback;
import de.cotech.hw.fido.FidoRegisterRequest;
import de.cotech.hw.fido.FidoRegisterResponse;
import de.cotech.hw.fido.FidoSecurityKey;
import de.cotech.hw.fido.FidoSecurityKeyConnectionMode;
import de.cotech.hw.fido.R;
import de.cotech.hw.fido.exceptions.FidoWrongKeyHandleException;
import de.cotech.hw.fido.internal.utils.AnimatedVectorDrawableHelper;
import de.cotech.hw.util.NfcStatusObserver;
import de.cotech.sweetspot.NfcSweetspotData;
import de.cotech.hw.util.HwTimber;


public class FidoDialogFragment extends BottomSheetDialogFragment implements SecurityKeyCallback<FidoSecurityKey> {
    private static final String FRAGMENT_TAG = "hwsecurity-fido-fragment";
    private static final String ARG_FIDO_REGISTER_REQUEST = "ARG_FIDO_REGISTER_REQUEST";
    private static final String ARG_FIDO_AUTHENTICATE_REQUEST = "ARG_FIDO_AUTHENTICATE_REQUEST";
    private static final String ARG_FIDO_OPTIONS = "de.cotech.hw.fido.ARG_FIDO_OPTIONS";

    private static final long TIME_DELAYED_STATE_CHANGE = 3000;

    private OnFidoRegisterCallback fidoRegisterCallback;
    private OnFidoAuthenticateCallback fidoAuthenticateCallback;

    private CoordinatorLayout coordinator;
    private FrameLayout bottomSheet;
    private ConstraintLayout innerBottomSheet;
    private Guideline guidelineForceHeight;

    private Button buttonCancel;

    private TextView textTitle;
    private TextView textDescription;
    private TextView textNfc;
    private TextView textUsb;
    private ImageView imageNfc;
    private ImageView imageNfcFullscreen;
    private ImageView imageUsb;

    private TextView textViewNfcDisabled;
    private Button buttonNfcDisabled;

    private TextView textError;
    private ImageView imageError;

    private ImageView sweetspotIndicator;
    private TextView textNfcFullscreen;

    private NfcStatusObserver nfcStatusObserver;

    private FidoDialogOptions options;
    private FidoRegisterRequest fidoRegisterRequest;
    private FidoAuthenticateRequest fidoAuthenticateRequest;

    private enum State {
        START,
        NFC_FULLSCREEN,
        NFC_SWEETSPOT,
        USB_INSERT,
        USB_PRESS_BUTTON,
        USB_SELECT_AND_PRESS_BUTTON,
        ERROR,
    }

    private State currentState;
    private State stateBeforeError;

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
        return inflater.inflate(R.layout.hwsecurity_fido_bottomsheet, container, false);
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

            textError.setText(R.string.hwsecurity_error_timeout);
            gotoState(State.ERROR);
            bottomSheet.postDelayed(() -> {
                if (!isAdded()) {
                    return;
                }
                dismiss();

                if (fidoAuthenticateRequest != null) {
                    fidoAuthenticateCallback.onFidoAuthenticateTimeout(fidoAuthenticateRequest);
                } else if (fidoRegisterRequest != null) {
                    fidoRegisterCallback.onFidoRegisterTimeout(fidoRegisterRequest);
                }
            }, TIME_DELAYED_STATE_CHANGE);
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

        innerBottomSheet = view.findViewById(R.id.hwSecurityFidoBottomSheet);
        guidelineForceHeight = view.findViewById(R.id.guidelineForceHeight);
        buttonCancel = view.findViewById(R.id.buttonCancel);
        textTitle = view.findViewById(R.id.textTitle);
        textDescription = view.findViewById(R.id.textDescription);
        textNfc = view.findViewById(R.id.textNfc);
        textNfcFullscreen = view.findViewById(R.id.textNfcFullscreen);
        textUsb = view.findViewById(R.id.textUsb);
        imageNfc = view.findViewById(R.id.imageNfc);
        imageNfcFullscreen = view.findViewById(R.id.imageNfcFullscreen);
        sweetspotIndicator = view.findViewById(R.id.imageNfcSweetspot);
        imageUsb = view.findViewById(R.id.imageUsb);
        imageError = view.findViewById(R.id.imageError);
        textError = view.findViewById(R.id.textError);
        textViewNfcDisabled = view.findViewById(R.id.textNfcDisabled);
        buttonNfcDisabled = view.findViewById(R.id.buttonNfcDisabled);

        nfcStatusObserver = new NfcStatusObserver(getContext(), this, this::showOrHideNfcDisabledView);

        buttonCancel.setOnClickListener(v -> getDialog().cancel());
    }

    @Override
    public void onResume() {
        super.onResume();
        if (currentState == State.START) {
            // re-check NFC status, maybe user is coming back from settings
            showOrHideNfcView();
        }
        if (currentState == null ||
                currentState == State.USB_INSERT ||
                currentState == State.USB_PRESS_BUTTON ||
                currentState == State.USB_SELECT_AND_PRESS_BUTTON) {
            gotoState(State.START);
        }
    }

    private void showOrHideNfcView() {
        boolean isNfcHardwareAvailable = SecurityKeyManager.getInstance().isNfcHardwareAvailable();
        textNfc.setVisibility(isNfcHardwareAvailable ? View.VISIBLE : View.GONE);
        imageNfc.setVisibility(isNfcHardwareAvailable ? View.VISIBLE : View.GONE);

        if (isNfcHardwareAvailable) {
            boolean nfcEnabled = nfcStatusObserver.isNfcEnabled();
            showOrHideNfcDisabledView(nfcEnabled);
        }
    }

    private void showOrHideNfcDisabledView(boolean nfcEnabled) {
        textViewNfcDisabled.setVisibility(nfcEnabled ? View.GONE : View.VISIBLE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
            buttonNfcDisabled.setOnClickListener(v -> startAndroidNfcConfigActivityWithHint());
            buttonNfcDisabled.setVisibility(nfcEnabled ? View.GONE : View.VISIBLE);
        }
        textNfc.setVisibility(nfcEnabled ? View.VISIBLE : View.INVISIBLE);
        imageNfc.setVisibility(nfcEnabled ? View.VISIBLE : View.INVISIBLE);
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    private void startAndroidNfcConfigActivityWithHint() {
        Toast.makeText(getContext().getApplicationContext(),
                R.string.hwsecurity_nfc_settings_toast, Toast.LENGTH_SHORT).show();
        startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
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
            return getResources().getString(R.string.hwsecurity_title_default_register);
        } else {
            return getResources().getString(R.string.hwsecurity_title_default_authenticate);
        }
    }

    private void gotoState(State newState) {
        switch (newState) {
            case START: {
                imageNfc.setOnClickListener(v -> gotoState(State.NFC_FULLSCREEN));
                imageUsb.setOnClickListener(v -> gotoState(State.USB_INSERT));
                animateStart();
                break;
            }
            case NFC_FULLSCREEN: {
                removeOnClickListener();
                animateSelectNfc();
                break;
            }
            case NFC_SWEETSPOT: {
                removeOnClickListener();
                showNfcSweetSpot();
                break;
            }
            case USB_INSERT: {
                removeOnClickListener();
                animateSelectUsb();
                break;
            }
            case USB_PRESS_BUTTON: {
                removeOnClickListener();
                animateUsbPressButton();
                break;
            }
            case USB_SELECT_AND_PRESS_BUTTON: {
                removeOnClickListener();
                animateSelectUsbAndPressButton();
                break;
            }
            case ERROR: {
                removeOnClickListener();
                animateError();
                break;
            }
        }
        currentState = newState;
    }

    private void removeOnClickListener() {
        imageNfc.setOnClickListener(null);
        imageUsb.setOnClickListener(null);
    }

    private void animateStart() {
        imageNfc.setImageResource(R.drawable.hwsecurity_nfc_start);
        imageUsb.setImageResource(R.drawable.hwsecurity_usb_start);
        buttonCancel.setText(R.string.hwsecurity_cancel);
        textTitle.setText(getStartTitle());
        textDescription.setText(R.string.hwsecurity_description_start);

        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);

        TransitionManager.go(new Scene(innerBottomSheet), selectModeTransition);
        showOrHideNfcView();
        imageUsb.setVisibility(View.VISIBLE);
        textUsb.setVisibility(View.VISIBLE);
        textTitle.setVisibility(View.VISIBLE);
        textDescription.setVisibility(View.VISIBLE);
        textError.setVisibility(View.GONE);
        imageError.setVisibility(View.GONE);
    }

    private void animateSelectNfc() {
        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                animateNfcFullscreen();
            }

            @Override
            public void onTransitionCancel(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionPause(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionResume(@NonNull Transition transition) {
            }
        });

        TransitionManager.go(new Scene(innerBottomSheet), selectModeTransition);
        imageUsb.setVisibility(View.GONE);
        imageNfc.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
        textTitle.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textError.setVisibility(View.GONE);
        imageError.setVisibility(View.GONE);
    }

    private void animateNfcFullscreen() {
        ValueAnimator bottomSheetFullscreenAnimator = ValueAnimator
                .ofInt(bottomSheet.getHeight(), coordinator.getHeight())
                .setDuration(250);

        bottomSheetFullscreenAnimator.addUpdateListener(animation -> {
            bottomSheet.getLayoutParams().height = (int) animation.getAnimatedValue();
            bottomSheet.requestLayout();
            guidelineForceHeight.setGuidelineEnd((int) animation.getAnimatedValue() - 100);
            guidelineForceHeight.requestLayout();
        });

        int colorFrom = getResources().getColor(R.color.hwSecurityWhite);
        int colorTo = resolveColorFromAttr(R.attr.hwSecuritySurfaceColor);
        ValueAnimator colorChange = ValueAnimator.ofObject(new ArgbEvaluator(), colorFrom, colorTo);
        colorChange.setDuration(100);
        colorChange.addUpdateListener(animator -> {
            innerBottomSheet.setBackgroundColor((int) animator.getAnimatedValue());
        });

        ObjectAnimator fadeInImageNfcFullscreen = ObjectAnimator
                .ofFloat(imageNfcFullscreen, View.ALPHA, 0, 1)
                .setDuration(150);
        fadeInImageNfcFullscreen.setStartDelay(50);
        fadeInImageNfcFullscreen.addListener(new Animator.AnimatorListener() {
            @Override
            public void onAnimationStart(Animator animation) {
                imageNfcFullscreen.setVisibility(View.VISIBLE);
            }

            @Override
            public void onAnimationEnd(Animator animation) {
            }

            @Override
            public void onAnimationCancel(Animator animation) {
            }

            @Override
            public void onAnimationRepeat(Animator animation) {
            }
        });

        bottomSheetFullscreenAnimator.addListener(new Animator.AnimatorListener() {
            @Override
            public void onAnimationStart(Animator animation) {
            }

            @Override
            public void onAnimationEnd(Animator animation) {
                animateNfcFinal();
            }

            @Override
            public void onAnimationCancel(Animator animation) {
            }

            @Override
            public void onAnimationRepeat(Animator animation) {
            }
        });

        List<Animator> items = new ArrayList<>();
        items.add(bottomSheetFullscreenAnimator);
        items.add(fadeInImageNfcFullscreen);
        items.add(colorChange);

        AnimatorSet set = new AnimatorSet();
        set.playTogether(items);
        set.setInterpolator(new AccelerateDecelerateInterpolator());
        set.start();
    }

    private void animateNfcFinal() {
        textNfcFullscreen.setText(R.string.hwsecurity_title_nfc_fullscreen);
        textNfcFullscreen.setVisibility(View.VISIBLE);

        Animatable2Compat.AnimationCallback animationCallback = new Animatable2Compat.AnimationCallback() {
            @Override
            public void onAnimationEnd(Drawable drawable) {
                if (!ViewCompat.isAttachedToWindow(imageNfcFullscreen)) {
                    return;
                }

                fadeToNfcSweetSpot();
            }
        };

        AnimatedVectorDrawableHelper.startAnimation(getActivity(), imageNfcFullscreen, R.drawable.hwsecurity_nfc_handling, animationCallback);
    }

    private void fadeToNfcSweetSpot() {
        Pair<Double, Double> nfcPosition = NfcSweetspotData.getSweetspotForBuildModel();
        if (nfcPosition == null) {
            HwTimber.d("No NFC sweetspot data available for this model.");
            return;
        }

        int colorFrom = resolveColorFromAttr(R.attr.hwSecuritySurfaceColor);
        int colorTo = getResources().getColor(R.color.hwSecurityWhite);
        ValueAnimator colorChange = ValueAnimator.ofObject(new ArgbEvaluator(), colorFrom, colorTo);
        colorChange.setDuration(150);
        colorChange.addUpdateListener(animator -> {
            innerBottomSheet.setBackgroundColor((int) animator.getAnimatedValue());
        });

        ObjectAnimator fadeOutImageNfcFullscreen = ObjectAnimator
                .ofFloat(imageNfcFullscreen, "alpha", 1, 0)
                .setDuration(150);

        fadeOutImageNfcFullscreen.addListener(new Animator.AnimatorListener() {
            @Override
            public void onAnimationStart(Animator animation) {
            }

            @Override
            public void onAnimationEnd(Animator animation) {
                gotoState(State.NFC_SWEETSPOT);
            }

            @Override
            public void onAnimationCancel(Animator animation) {
            }

            @Override
            public void onAnimationRepeat(Animator animation) {
            }
        });

        List<Animator> items = new ArrayList<>();
        items.add(colorChange);
        items.add(fadeOutImageNfcFullscreen);

        AnimatorSet set = new AnimatorSet();
        set.playTogether(items);
        set.start();
    }

    private void showNfcSweetSpot() {
        Pair<Double, Double> nfcPosition = NfcSweetspotData.getSweetspotForBuildModel();

        Dialog dialog = getDialog();
        if (dialog == null) {
            return;
        }

        DisplayMetrics metrics = new DisplayMetrics();
        dialog.getWindow().getWindowManager().getDefaultDisplay().getMetrics(metrics);

        final float translationX = (float) (metrics.widthPixels * nfcPosition.first);
        final float translationY = (float) (metrics.heightPixels * nfcPosition.second);

        sweetspotIndicator.post(() -> {
            sweetspotIndicator.setTranslationX(translationX - sweetspotIndicator.getWidth() / 2);
            sweetspotIndicator.setTranslationY(translationY - sweetspotIndicator.getHeight() / 2);

            TransitionManager.beginDelayedTransition(innerBottomSheet);
            sweetspotIndicator.setVisibility(View.VISIBLE);
            textNfcFullscreen.setVisibility(View.VISIBLE);
            imageNfcFullscreen.setVisibility(View.GONE);
            imageError.setVisibility(View.GONE);
            textError.setVisibility(View.GONE);
        });

        AnimatedVectorDrawableHelper.startAndLoopAnimation(getActivity(), sweetspotIndicator, R.drawable.hwsecurity_nfc_sweet_spot_a);
    }

    private void animateSelectUsb() {
        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                AnimatedVectorDrawableHelper.startAndLoopAnimation(getActivity(), imageUsb, R.drawable.hwsecurity_usb_handling_a);
            }

            @Override
            public void onTransitionCancel(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionPause(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionResume(@NonNull Transition transition) {
            }
        });

        TransitionManager.go(new Scene(innerBottomSheet), selectModeTransition);
        textTitle.setText(R.string.hwsecurity_title_usb_selected);
        imageNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
        textError.setVisibility(View.GONE);
        imageError.setVisibility(View.GONE);
    }

    private void animateSelectUsbAndPressButton() {
        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                AnimatedVectorDrawableHelper.startAndLoopAnimation(getActivity(), imageUsb, R.drawable.hwsecurity_usb_handling_b);
            }

            @Override
            public void onTransitionCancel(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionPause(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionResume(@NonNull Transition transition) {
            }
        });

        TransitionManager.go(new Scene(innerBottomSheet), selectModeTransition);
        textTitle.setText(R.string.hwsecurity_title_usb_button);
        imageNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
        textError.setVisibility(View.GONE);
        imageError.setVisibility(View.GONE);
    }

    private void animateUsbPressButton() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        textTitle.setText(R.string.hwsecurity_title_usb_button);
        AnimatedVectorDrawableHelper.startAndLoopAnimation(getActivity(), imageUsb, R.drawable.hwsecurity_usb_handling_b);
    }

    private void animateError() {
        TransitionManager.beginDelayedTransition(innerBottomSheet);
        textTitle.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        imageNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        imageUsb.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
        textNfcFullscreen.setVisibility(View.GONE);
        imageNfcFullscreen.setVisibility(View.GONE);
        textError.setVisibility(View.VISIBLE);
        imageError.setVisibility(View.VISIBLE);

        AnimatedVectorDrawableHelper.startAnimation(getActivity(), imageError, R.drawable.hwsecurity_error);
    }

    @UiThread
    @Override
    public void onSecurityKeyDiscovered(@NonNull FidoSecurityKey securityKey) {
        switch (currentState) {
            case START: {
                if (securityKey.isTransportUsb()) {
                    gotoState(State.USB_SELECT_AND_PRESS_BUTTON);
                }
                break;
            }
            case USB_INSERT: {
                if (securityKey.isTransportUsb()) {
                    gotoState(State.USB_PRESS_BUTTON);
                }
                break;
            }
            default: {
                HwTimber.d("onSecurityKeyDiscovered unhandled state: %s", currentState.name());
            }
        }

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

        switch (currentState) {
            case USB_PRESS_BUTTON:
            case USB_SELECT_AND_PRESS_BUTTON:
                gotoState(State.START);
            default:
                HwTimber.d("onSecurityKeyDisconnected unhandled state: %s", currentState.name());
        }
    }

    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
        handleError(exception);
    }

    private void handleError(IOException exception) {
        HwTimber.d(exception);

        if (currentState == State.ERROR) {
            // keep stateBeforeError
        } else if (currentState == State.NFC_FULLSCREEN || currentState == State.NFC_SWEETSPOT) {
            stateBeforeError = State.NFC_SWEETSPOT;
        } else {
            stateBeforeError = State.START;
        }

        try {
            throw exception;
        } catch (FidoWrongKeyHandleException e) {
            showError(getString(R.string.hwsecurity_error_wrong_key_handle));
        } catch (SecurityKeyException e) {
            showError(getString(R.string.hwsecurity_error_internal, e.getShortErrorName()));
        } catch (TagLostException e) {
            // not handled
        } catch (IOException e) {
            showError(getString(R.string.hwsecurity_error_internal, e.getMessage()));
        }
    }

    private void showError(String text) {
        textError.setText(text);
        gotoState(State.ERROR);
        bottomSheet.postDelayed(() -> {
            if (!isAdded()) {
                return;
            }
            gotoState(stateBeforeError);
        }, TIME_DELAYED_STATE_CHANGE);
    }

    private int resolveColorFromAttr(@AttrRes int resId) {
        TypedValue outValue = new TypedValue();
        bottomSheet.getContext().getTheme().resolveAttribute(resId, outValue, true);
        return outValue.data;
    }

}
