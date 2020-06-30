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

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ArgbEvaluator;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.DisplayMetrics;
import android.util.Pair;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.ViewCompat;
import androidx.lifecycle.LifecycleObserver;
import androidx.transition.TransitionManager;
import androidx.vectordrawable.graphics.drawable.Animatable2Compat;

import java.util.ArrayList;
import java.util.List;

import de.cotech.hw.ui.R;
import de.cotech.hw.util.HwTimber;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class NfcFullscreenView implements LifecycleObserver {
    private Context context;

    private ViewGroup view;
    private ConstraintLayout innerBottomSheet;

    private ImageView imageNfcSweetspot;
    private TextView textNfcFullscreen;
    private ImageView imageNfcFullscreen;

    private Guideline guidelineForceHeight;

    private NfcSweetspotData nfcSweetspotData;

    public NfcFullscreenView(@NonNull ViewGroup view, ConstraintLayout innerBottomSheet) {
        this.context = view.getContext();

        this.view = view;

        this.innerBottomSheet = innerBottomSheet;

        imageNfcSweetspot = view.findViewById(R.id.imageNfcSweetspot);
        textNfcFullscreen = view.findViewById(R.id.textNfcFullscreen);
        imageNfcFullscreen = view.findViewById(R.id.imageNfcFullscreen);

        guidelineForceHeight = innerBottomSheet.findViewById(R.id.guidelineForceHeight);

        nfcSweetspotData = NfcSweetspotData.getInstance(context);
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
    }

    public int getVisibility() {
        return view.getVisibility();
    }

    public void animateNfcFullscreen(Dialog dialog) {
        CoordinatorLayout coordinator = dialog.findViewById(com.google.android.material.R.id.coordinator);
        FrameLayout bottomSheet = dialog.findViewById(com.google.android.material.R.id.design_bottom_sheet);

        ValueAnimator bottomSheetFullscreenAnimator = ValueAnimator
                .ofInt(bottomSheet.getHeight(), coordinator.getHeight())
                .setDuration(250);

        bottomSheetFullscreenAnimator.addUpdateListener(animation -> {
            bottomSheet.getLayoutParams().height = (int) animation.getAnimatedValue();
            bottomSheet.requestLayout();
            guidelineForceHeight.setGuidelineEnd((int) animation.getAnimatedValue() - 100);
            guidelineForceHeight.requestLayout();
        });

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
                animateNfcFinal(dialog);
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

    private void animateNfcFinal(Dialog dialog) {
        textNfcFullscreen.setText(R.string.hwsecurity_ui_title_nfc_fullscreen);
        textNfcFullscreen.setVisibility(View.VISIBLE);

        Animatable2Compat.AnimationCallback animationCallback = new Animatable2Compat.AnimationCallback() {
            @Override
            public void onAnimationEnd(Drawable drawable) {
                if (!ViewCompat.isAttachedToWindow(imageNfcFullscreen)) {
                    return;
                }

                fadeToNfcSweetSpot(dialog);
            }
        };

        AnimatedVectorDrawableHelper.startAnimation(imageNfcFullscreen, R.drawable.hwsecurity_nfc_handling, animationCallback);
    }

    private void fadeToNfcSweetSpot(Dialog dialog) {
        Pair<Double, Double> nfcPosition = nfcSweetspotData.getSweetspotForBuildModel();
        if (nfcPosition == null) {
            HwTimber.d("No NFC sweetspot data available for this model.");
            return;
        }

        int colorFrom = resolveColorFromAttr(R.attr.hwSecuritySurfaceColor);
        int colorTo = context.getResources().getColor(R.color.hwSecurityWhite);
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
                showNfcSweetSpot(dialog);
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

    private void showNfcSweetSpot(Dialog dialog) {
        Pair<Double, Double> nfcPosition = nfcSweetspotData.getSweetspotForBuildModel();

        if (dialog == null) {
            return;
        }

        DisplayMetrics metrics = new DisplayMetrics();
        dialog.getWindow().getWindowManager().getDefaultDisplay().getMetrics(metrics);

        float statusBarHeight = getStatusbarHeight(dialog.getWindow());

        final float translationX = (float) (metrics.widthPixels * nfcPosition.first);
        final float translationY = (float) (metrics.heightPixels * nfcPosition.second) + statusBarHeight;

        imageNfcSweetspot.post(() -> {
            imageNfcSweetspot.setTranslationX(translationX - imageNfcSweetspot.getWidth() / 2);
            imageNfcSweetspot.setTranslationY(translationY - imageNfcSweetspot.getHeight() / 2);

            TransitionManager.beginDelayedTransition(innerBottomSheet);
            imageNfcSweetspot.setVisibility(View.VISIBLE);
            textNfcFullscreen.setVisibility(View.VISIBLE);
            imageNfcFullscreen.setVisibility(View.GONE);
        });

        AnimatedVectorDrawableHelper.startAndLoopAnimation(imageNfcSweetspot, R.drawable.hwsecurity_nfc_sweet_spot_a);
    }

    private static int getStatusbarHeight(Window window) {
        Rect rectangle = new Rect();
        window.getDecorView().getWindowVisibleDisplayFrame(rectangle);
        int statusBarHeight = rectangle.top;
        int contentViewTop = window.findViewById(Window.ID_ANDROID_CONTENT).getTop();
        return contentViewTop - statusBarHeight;
    }

    private int resolveColorFromAttr(@AttrRes int resId) {
        TypedValue outValue = new TypedValue();
        // must be the themed context to work correctly on Android < 5
        innerBottomSheet.getContext().getTheme().resolveAttribute(resId, outValue, true);
        return outValue.data;
    }

}
