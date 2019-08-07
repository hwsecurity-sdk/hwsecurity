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

package de.cotech.hw.ui.internal;

import android.animation.*;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.*;

import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.RestrictTo;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.transition.AutoTransition;
import androidx.transition.Scene;
import androidx.transition.Transition;
import androidx.transition.TransitionManager;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.ui.R;
import de.cotech.hw.util.NfcStatusObserver;

import java.util.ArrayList;
import java.util.List;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class SecurityKeyFormFactor {
    private Context context;

    private ViewGroup view;
    private ConstraintLayout innerBottomSheet;
    private Guideline guidelineForceHeight;

    private TextView textTitle;
    private TextView textDescription;
    private TextView textNfc;
    private TextView textUsb;
    private ImageView imageNfc;
    private ImageView imageNfcFullscreen;
    private ImageView imageUsb;

    private TextView textViewNfcDisabled;
    private Button buttonNfcDisabled;

    private ImageView sweetspotIndicator;
    private TextView textNfcFullscreen;

    public SecurityKeyFormFactor(@NonNull ViewGroup view, ConstraintLayout innerBottomSheet) {
        this.context = view.getContext();

        this.view = view;
        this.innerBottomSheet = innerBottomSheet;

        guidelineForceHeight = innerBottomSheet.findViewById(R.id.guidelineForceHeight);
        textTitle = innerBottomSheet.findViewById(R.id.textTitle);
        textDescription = innerBottomSheet.findViewById(R.id.textDescription);

        textNfc = view.findViewById(R.id.textNfc);
        textNfcFullscreen = view.findViewById(R.id.textNfcFullscreen);
        textUsb = view.findViewById(R.id.textUsb);
        imageNfc = view.findViewById(R.id.imageNfc);
        imageNfcFullscreen = view.findViewById(R.id.imageNfcFullscreen);
        sweetspotIndicator = view.findViewById(R.id.imageNfcSweetspot);
        imageUsb = view.findViewById(R.id.imageUsb);
        textViewNfcDisabled = view.findViewById(R.id.textNfcDisabled);
        buttonNfcDisabled = view.findViewById(R.id.buttonNfcDisabled);

        imageNfc.setOnClickListener(v -> animateSelectNfc());
        imageUsb.setOnClickListener(v -> animateSelectUsb());
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
    }

    public int getVisibility() {
        return view.getVisibility();
    }

    private void showOrHideNfcView(NfcStatusObserver nfcStatusObserver) {
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
        Toast.makeText(context.getApplicationContext(),
                R.string.hwsecurity_nfc_settings_toast, Toast.LENGTH_SHORT).show();
        context.startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
    }


    private void removeOnClickListener() {
        imageNfc.setOnClickListener(null);
        imageUsb.setOnClickListener(null);
    }

    private int resolveColorFromAttr(@AttrRes int resId) {
        TypedValue outValue = new TypedValue();
        context.getTheme().resolveAttribute(resId, outValue, true);
        return outValue.data;
    }

    private void animateSelectNfc() {
        removeOnClickListener();

        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                int colorFrom = context.getResources().getColor(R.color.hwSecurityWhite);
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
                        AnimatedVectorDrawableHelper.startAndLoopAnimation(context, imageNfcFullscreen, R.drawable.hwsecurity_nfc_handling);
                    }

                    @Override
                    public void onAnimationCancel(Animator animation) {
                    }

                    @Override
                    public void onAnimationRepeat(Animator animation) {
                    }
                });

                ObjectAnimator fadeOutNfcFullscreen = ObjectAnimator
                        .ofFloat(imageNfc, View.ALPHA, 1, 0)
                        .setDuration(150);
                fadeInImageNfcFullscreen.setStartDelay(50);
                fadeInImageNfcFullscreen.addListener(new Animator.AnimatorListener() {
                    @Override
                    public void onAnimationStart(Animator animation) {
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

                List<Animator> items = new ArrayList<>();
                items.add(fadeInImageNfcFullscreen);
                items.add(fadeOutNfcFullscreen);
                items.add(colorChange);

                AnimatorSet set = new AnimatorSet();
                set.playTogether(items);
                set.setInterpolator(new AccelerateDecelerateInterpolator());
                set.start();
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

        TransitionManager.go(new Scene(view), selectModeTransition);
        textTitle.setText(R.string.hwsecurity_title_nfc_fullscreen);
        imageUsb.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
    }

    private void animateSelectUsb() {
        removeOnClickListener();

        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                AnimatedVectorDrawableHelper.startAndLoopAnimation(context, imageUsb, R.drawable.hwsecurity_usb_handling_a);
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

        TransitionManager.go(new Scene(view), selectModeTransition);
        textTitle.setText(R.string.hwsecurity_title_usb_selected);
        imageNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
    }

}
