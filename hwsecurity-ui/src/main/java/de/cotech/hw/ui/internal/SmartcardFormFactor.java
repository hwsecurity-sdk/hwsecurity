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

import android.content.Context;
import android.graphics.drawable.Animatable;
import android.view.View;
import android.widget.ImageView;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;

import de.cotech.hw.ui.R;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class SmartcardFormFactor {
    private Context context;

    private View view;
    private ImageView smartcardAnimation;

    public SmartcardFormFactor(@NonNull View view) {
        this.context = view.getContext();
        this.view = view;

        smartcardAnimation = view.findViewById(R.id.smartcardAnimation);

        smartcardAnimation.setOnClickListener(v -> {
                    Animatable animatable = (Animatable) smartcardAnimation.getDrawable();
                    animatable.stop();
                    startSmartcardAnimation();
                }
        );
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
    }

    public int getVisibility() {
        return view.getVisibility();
    }

    public void startSmartcardAnimation() {
        AnimatedVectorDrawableHelper.startAnimation(context, smartcardAnimation, R.drawable.hwsecurity_smartcard_animation);
    }
}
