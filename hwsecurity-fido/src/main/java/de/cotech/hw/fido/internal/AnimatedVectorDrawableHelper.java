package de.cotech.hw.fido.internal;

import android.content.Context;
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

    public static void startAnimation(Context context, ImageView imageView, int resId) {
        startAnimation(context, imageView, resId, null);
    }

    public static void startAnimation(Context context, ImageView imageView, int resId, Animatable2Compat.AnimationCallback animationCallback) {
        if (Build.VERSION.SDK_INT <= 24) {
            AnimatedVectorDrawableCompat avdCompat = setAndStartAnimatedVectorDrawableSdk24(context, imageView, resId);
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

    public static void startAndLoopAnimation(Context context, ImageView imageView, int resId) {
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
                        AnimatedVectorDrawableCompat avdCompat = setAndStartAnimatedVectorDrawableSdk24(context, imageView, resId);
                        avdCompat.registerAnimationCallback(this);
                    } else {
                        ((Animatable) drawable).start();
                    }
                });
            }
        };

        if (Build.VERSION.SDK_INT <= 24) {
            AnimatedVectorDrawableCompat avdCompat = setAndStartAnimatedVectorDrawableSdk24(context, imageView, resId);
            avdCompat.registerAnimationCallback(animationCallback);
        } else {
            imageView.setImageResource(resId);
            AnimatedVectorDrawableCompat.registerAnimationCallback(imageView.getDrawable(), animationCallback);
            Animatable animatable = (Animatable) imageView.getDrawable();
            animatable.start();
        }
    }

    private static AnimatedVectorDrawableCompat setAndStartAnimatedVectorDrawableSdk24(Context context, ImageView imageView, int resId) {
        AnimatedVectorDrawableCompat avdCompat = AnimatedVectorDrawableCompat.create(context, resId);

        // on SDK <= 24, the alphaFill values are not resetted properly to their initial state
        // The states of AnimatedVectorDrawables are stored centrally per resource.
        // Thus, making the drawable mutate allows it to have a completely new state
        avdCompat.mutate();

        imageView.setImageDrawable(avdCompat);
        avdCompat.start();

        return avdCompat;
    }
}
