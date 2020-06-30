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

package de.cotech.hw.fido2.internal.utils;

import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.widget.ImageView;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.core.view.ViewCompat;
import androidx.vectordrawable.graphics.drawable.Animatable2Compat;
import androidx.vectordrawable.graphics.drawable.AnimatedVectorDrawableCompat;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class AnimatedVectorDrawableHelper {

    public static void startAnimation(ImageView imageView, int resId) {
        startAnimation(imageView, resId, null);
    }

    public static void startAnimation(ImageView imageView, int resId, Animatable2Compat.AnimationCallback animationCallback) {
        if (Build.VERSION.SDK_INT <= 24) {
            AnimatedVectorDrawableCompat avdCompat = setAndStartAnimatedVectorDrawableSdk24(imageView, resId);
            if (animationCallback != null) {
                avdCompat.registerAnimationCallback(animationCallback);
            }
        } else {
            if (animationCallback != null) {
                AnimatedVectorDrawableCompat.registerAnimationCallback(imageView.getDrawable(), animationCallback);
            }
            Animatable animatable = (Animatable) imageView.getDrawable();
            animatable.start();
        }
    }

    public static void startAndLoopAnimation(ImageView imageView, int resId) {
        Animatable2Compat.AnimationCallback animationCallback = new Animatable2Compat.AnimationCallback() {
            @NonNull
            private final Handler fHandler = new Handler(Looper.getMainLooper());

            @Override
            public void onAnimationEnd(@NonNull Drawable drawable) {
                if (!ViewCompat.isAttachedToWindow(imageView)) {
                    return;
                }

                fHandler.post(() -> {
                    if (Build.VERSION.SDK_INT <= 24) {
                        AnimatedVectorDrawableCompat avdCompat = setAndStartAnimatedVectorDrawableSdk24(imageView, resId);
                        avdCompat.registerAnimationCallback(this);
                    } else {
                        ((Animatable) drawable).start();
                    }
                });
            }
        };

        if (Build.VERSION.SDK_INT <= 24) {
            AnimatedVectorDrawableCompat avdCompat = setAndStartAnimatedVectorDrawableSdk24(imageView, resId);
            avdCompat.registerAnimationCallback(animationCallback);
        } else {
            imageView.setImageResource(resId);
            AnimatedVectorDrawableCompat.registerAnimationCallback(imageView.getDrawable(), animationCallback);
            Animatable animatable = (Animatable) imageView.getDrawable();
            animatable.start();
        }
    }

    private static AnimatedVectorDrawableCompat setAndStartAnimatedVectorDrawableSdk24(ImageView imageView, int resId) {
        AnimatedVectorDrawableCompat avdCompat = AnimatedVectorDrawableCompat.create(imageView.getContext(), resId);

        // on SDK <= 24, the alphaFill values are not resetted properly to their initial state
        // The states of AnimatedVectorDrawables are stored centrally per resource.
        // Thus, making the drawable mutate allows it to have a completely new state
        avdCompat.mutate();

        imageView.setImageDrawable(avdCompat);
        avdCompat.start();

        return avdCompat;
    }
}
