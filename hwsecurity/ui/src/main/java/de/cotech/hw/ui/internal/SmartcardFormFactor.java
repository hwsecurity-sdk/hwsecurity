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

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Animatable;
import android.os.Build;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.RestrictTo;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.OnLifecycleEvent;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.ui.R;
import de.cotech.hw.util.NfcStatusObserver;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class SmartcardFormFactor implements LifecycleObserver {
    private Context context;

    private View view;
    private ImageView smartcardAnimation;

    private TextView textViewNfcDisabled;
    private Button buttonNfcDisabled;

    private NfcStatusObserver nfcStatusObserver;

    public SmartcardFormFactor(@NonNull View view, LifecycleOwner lifecycleOwner) {
        this.context = view.getContext();
        this.view = view;

        lifecycleOwner.getLifecycle().addObserver(this);
        nfcStatusObserver = new NfcStatusObserver(context, lifecycleOwner, this::showOrHideNfcDisabledView);

        textViewNfcDisabled = view.findViewById(R.id.textNfcDisabled);
        buttonNfcDisabled = view.findViewById(R.id.buttonNfcDisabled);
        smartcardAnimation = view.findViewById(R.id.smartcardAnimation);

        smartcardAnimation.setOnClickListener(v -> {
                    Animatable animatable = (Animatable) smartcardAnimation.getDrawable();
                    animatable.stop();
                    AnimatedVectorDrawableHelper.startAnimation(smartcardAnimation, R.drawable.hwsecurity_smartcard_animation);
                }
        );

        showOrHideNfcView();
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_RESUME)
    public void onResume() {
        // re-check NFC status, maybe user is coming back from settings
        if (getVisibility() == View.VISIBLE) {
            showOrHideNfcView();
        }
    }

    private void showOrHideNfcView() {
        boolean isNfcHardwareAvailable = SecurityKeyManager.getInstance().isNfcHardwareAvailable();
        smartcardAnimation.setVisibility(isNfcHardwareAvailable ? View.VISIBLE : View.GONE);

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
        smartcardAnimation.setVisibility(nfcEnabled ? View.VISIBLE : View.INVISIBLE);
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    private void startAndroidNfcConfigActivityWithHint() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.startActivity(new Intent(Settings.Panel.ACTION_NFC));
        } else {
            Toast.makeText(context.getApplicationContext(),
                    R.string.hwsecurity_ui_nfc_settings_toast, Toast.LENGTH_LONG).show();
            context.startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
        }
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
        if (visibility == View.VISIBLE) {
            AnimatedVectorDrawableHelper.startAnimation(smartcardAnimation, R.drawable.hwsecurity_smartcard_animation);
        } else {
            Animatable animatable = (Animatable) smartcardAnimation.getDrawable();
            animatable.stop();
        }
    }

    public int getVisibility() {
        return view.getVisibility();
    }

}
