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
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.RestrictTo;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.OnLifecycleEvent;
import androidx.transition.AutoTransition;
import androidx.transition.Scene;
import androidx.transition.Transition;
import androidx.transition.TransitionManager;

import de.cotech.hw.SecurityKeyManager;
import de.cotech.hw.ui.R;
import de.cotech.hw.util.NfcStatusObserver;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class SecurityKeyFormFactor implements LifecycleObserver {
    private Context context;

    private ViewGroup view;

    private TextView textTitle;
    private TextView textDescription;

    private TextView textNfc;
    private TextView textUsb;
    private ImageView imageNfc;
    private ImageView imageUsb;

    private TextView textViewNfcDisabled;
    private Button buttonNfcDisabled;

    private NfcStatusObserver nfcStatusObserver;

    private SelectTransportCallback callback;

    public interface SelectTransportCallback {
        void screeFullscreenNfc();

        void onSecurityKeyFormFactorClickUsb();
    }

    public SecurityKeyFormFactor(@NonNull ViewGroup view, LifecycleOwner lifecycleOwner, SelectTransportCallback callback, ConstraintLayout innerBottomSheet, boolean showSdkButton) {
        this.context = view.getContext();

        this.view = view;
        this.callback = callback;

        lifecycleOwner.getLifecycle().addObserver(this);
        nfcStatusObserver = new NfcStatusObserver(context, lifecycleOwner, this::showOrHideNfcDisabledView);

        textTitle = innerBottomSheet.findViewById(R.id.textTitle);
        textDescription = innerBottomSheet.findViewById(R.id.textDescription);

        textNfc = view.findViewById(R.id.textNfc);
        textUsb = view.findViewById(R.id.textUsb);
        imageNfc = view.findViewById(R.id.imageNfc);
        imageUsb = view.findViewById(R.id.imageUsb);
        textViewNfcDisabled = view.findViewById(R.id.textNfcDisabled);
        buttonNfcDisabled = view.findViewById(R.id.buttonNfcDisabled);
        ImageButton sdkButton = view.findViewById(R.id.buttonSdk);

        sdkButton.setVisibility(showSdkButton ? View.VISIBLE : View.GONE);
        sdkButton.setOnClickListener(v -> {
            String packageName = context.getPackageName();
            String url = "https://hwsecurity.dev/?pk_campaign=sdk&pk_source=" + packageName;
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setData(Uri.parse(url));
            context.startActivity(i);
        });

        imageNfc.setOnClickListener(v -> animateSelectNfc());
        imageUsb.setOnClickListener(v -> {
            callback.onSecurityKeyFormFactorClickUsb();
            animateSelectUsb();
        });

        showOrHideNfcView();
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
    }

    public int getVisibility() {
        return view.getVisibility();
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.startActivity(new Intent(Settings.Panel.ACTION_NFC));
        } else {
            Toast.makeText(context.getApplicationContext(),
                    R.string.hwsecurity_ui_nfc_settings_toast, Toast.LENGTH_LONG).show();
            context.startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
        }
    }

    private void removeOnClickListener() {
        imageNfc.setOnClickListener(null);
        imageUsb.setOnClickListener(null);
    }

    public void resetAnimation() {
        imageNfc.setImageResource(R.drawable.hwsecurity_nfc_start);
        imageUsb.setImageResource(R.drawable.hwsecurity_usb_start);

        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);

        TransitionManager.go(new Scene(view), selectModeTransition);
        showOrHideNfcView();
        imageUsb.setVisibility(View.VISIBLE);
        textUsb.setVisibility(View.VISIBLE);
    }

    public void animateSelectNfc() {
        removeOnClickListener();

        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                callback.screeFullscreenNfc();
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
        textTitle.setText(R.string.hwsecurity_ui_title_nfc_fullscreen);
        imageUsb.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
    }

    public void animateSelectUsb() {
        removeOnClickListener();

        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                AnimatedVectorDrawableHelper.startAndLoopAnimation(imageUsb, R.drawable.hwsecurity_usb_handling_a);
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
        textTitle.setText(R.string.hwsecurity_ui_title_usb_selected);
        imageNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
    }

    public void animateSelectUsbAndPressButton() {
        AutoTransition selectModeTransition = new AutoTransition();
        selectModeTransition.setDuration(150);
        selectModeTransition.addListener(new Transition.TransitionListener() {
            @Override
            public void onTransitionStart(@NonNull Transition transition) {
            }

            @Override
            public void onTransitionEnd(@NonNull Transition transition) {
                AnimatedVectorDrawableHelper.startAndLoopAnimation(imageUsb, R.drawable.hwsecurity_usb_handling_b);
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
        textTitle.setText(R.string.hwsecurity_ui_title_usb_button);
        imageNfc.setVisibility(View.GONE);
        textViewNfcDisabled.setVisibility(View.GONE);
        buttonNfcDisabled.setVisibility(View.GONE);
        textDescription.setVisibility(View.GONE);
        textNfc.setVisibility(View.GONE);
        textUsb.setVisibility(View.GONE);
    }

    public void animateUsbPressButton() {
        textTitle.setText(R.string.hwsecurity_ui_title_usb_button);
        AnimatedVectorDrawableHelper.startAndLoopAnimation(imageUsb, R.drawable.hwsecurity_usb_handling_b);
    }

}
