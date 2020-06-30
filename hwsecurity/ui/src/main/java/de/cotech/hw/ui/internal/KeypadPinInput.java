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
import android.graphics.Color;
import android.os.Build;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;

import androidx.annotation.DrawableRes;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.constraintlayout.widget.ConstraintLayout;

import java.util.ArrayList;

import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.R;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class KeypadPinInput extends PinInput {
    private Context context;

    private Integer pinLength;
    private boolean fixedLength;

    private ConstraintLayout view;
    private LinearLayout pinCirclesLayout;
    private Button keypadConfirm;
    private Button[] keypadButtons;
    private ArrayList<ImageView> pinCircles;
    private static final int CIRCLE_MARGIN_START = 8;
    private static final int CIRCLE_SIZE = 24;

    // NOTE: Following Android design: Android AOSP lock screen allows PINs with a maximum of 16 digits
    public static final int PIN_MAX_DISPLAY_LENGTH = 16;
    private byte[] pin;
    private int pinPosition;

    private PinInputCallback callback;

    public void setPinInputCallback(PinInputCallback callback) {
        this.callback = callback;
    }

    public KeypadPinInput(@NonNull View view) {
        this.context = view.getContext();
        this.pinCirclesLayout = view.findViewById(R.id.pinCirclesLayout);
        this.keypadConfirm = view.findViewById(R.id.keypadButtonConfirm);
        this.view = (ConstraintLayout) view;

        view.setOnKeyListener((v, keyCode, event) -> handleHardwareKeys(keyCode, event));

        keypadButtons = new Button[]{view.findViewById(R.id.keypadButtonNo0),
                view.findViewById(R.id.keypadButtonNo1), view.findViewById(R.id.keypadButtonNo2),
                view.findViewById(R.id.keypadButtonNo3), view.findViewById(R.id.keypadButtonNo4),
                view.findViewById(R.id.keypadButtonNo5), view.findViewById(R.id.keypadButtonNo6),
                view.findViewById(R.id.keypadButtonNo7), view.findViewById(R.id.keypadButtonNo8),
                view.findViewById(R.id.keypadButtonNo9)};

        keypadButtons[0].setOnClickListener(v -> addPinNumber((byte) '0'));
        keypadButtons[1].setOnClickListener(v -> addPinNumber((byte) '1'));
        keypadButtons[2].setOnClickListener(v -> addPinNumber((byte) '2'));
        keypadButtons[3].setOnClickListener(v -> addPinNumber((byte) '3'));
        keypadButtons[4].setOnClickListener(v -> addPinNumber((byte) '4'));
        keypadButtons[5].setOnClickListener(v -> addPinNumber((byte) '5'));
        keypadButtons[6].setOnClickListener(v -> addPinNumber((byte) '6'));
        keypadButtons[7].setOnClickListener(v -> addPinNumber((byte) '7'));
        keypadButtons[8].setOnClickListener(v -> addPinNumber((byte) '8'));
        keypadButtons[9].setOnClickListener(v -> addPinNumber((byte) '9'));
        view.findViewById(R.id.keypadButtonDelete).setOnClickListener(v -> deletePinNumber());
        view.findViewById(R.id.keypadButtonDelete).setOnLongClickListener(v -> {
            deleteAllPinNumbers();
            return true;
        });
        view.findViewById(R.id.keypadButtonConfirm).setOnClickListener(v -> confirmPin());
    }

    private boolean handleHardwareKeys(int keyCode, KeyEvent event) {
        if (event.getAction() == KeyEvent.ACTION_UP) {
            switch (keyCode) {
                case KeyEvent.KEYCODE_0:
                    addPinNumber((byte) '0');
                    return true;
                case KeyEvent.KEYCODE_1:
                    addPinNumber((byte) '1');
                    return true;
                case KeyEvent.KEYCODE_2:
                    addPinNumber((byte) '2');
                    return true;
                case KeyEvent.KEYCODE_3:
                    addPinNumber((byte) '3');
                    return true;
                case KeyEvent.KEYCODE_4:
                    addPinNumber((byte) '4');
                    return true;
                case KeyEvent.KEYCODE_5:
                    addPinNumber((byte) '5');
                    return true;
                case KeyEvent.KEYCODE_6:
                    addPinNumber((byte) '6');
                    return true;
                case KeyEvent.KEYCODE_7:
                    addPinNumber((byte) '7');
                    return true;
                case KeyEvent.KEYCODE_8:
                    addPinNumber((byte) '8');
                    return true;
                case KeyEvent.KEYCODE_9:
                    addPinNumber((byte) '9');
                    return true;
                case KeyEvent.KEYCODE_DEL:
                    deletePinNumber();
                    return true;
                default:
                    return false;
            }
        } else {
            return false;
        }
    }

    private void setNumberButtonsEnabled(boolean enabled) {
        for (Button keypadButton : keypadButtons) {
            if (enabled) {
                keypadButton.setEnabled(true);
                keypadButton.setTextColor(Color.parseColor("#000000"));
            } else {
                keypadButton.setEnabled(false);
                keypadButton.setTextColor(Color.parseColor("#d3d3d3"));
            }
        }
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
        if (visibility == View.VISIBLE) {
            // get focus on view to handle hardware keyboard
            view.requestFocus();
        }
    }

    public int getVisibility() {
        return view.getVisibility();
    }

    public void reset(Integer pinLength) {
        this.pinLength = pinLength;
        fixedLength = pinLength != null;

        pin = new byte[PIN_MAX_DISPLAY_LENGTH];
        pinPosition = 0;

        pinCirclesLayout.removeAllViews();
        pinCircles = new ArrayList<>();

        if (fixedLength) {
            keypadConfirm.setVisibility(View.INVISIBLE);
            //noinspection ConstantConditions
            for (int i = 0; i < pinLength; i++) {
                addPinCircleImageView(R.drawable.hwsecurity_pin_circle);
            }
        } else {
            keypadConfirm.setVisibility(View.VISIBLE);
        }
    }

    private int getPinMaxLength() {
        if (fixedLength) {
            return pinLength;
        } else {
            return PIN_MAX_DISPLAY_LENGTH;
        }
    }

    private void addPinNumber(byte number) {
        if (pinPosition < getPinMaxLength()) {
            pin[pinPosition] = number;
            addPinCircle();
            pinPosition++;
        }
        if (pinPosition == getPinMaxLength()) {
            if (fixedLength) {
                callback.onPinEntered(getPinAndClear());
            } else {
                setNumberButtonsEnabled(false);
            }
        }
    }

    private void deletePinNumber() {
        if (pinPosition > 0) {
            pinPosition--;
            pin[pinPosition] = 'X';

            removePinCircle();
        }
    }

    private void deleteAllPinNumbers() {
        while (pinPosition > 0) {
            deletePinNumber();
        }
    }

    private void addPinCircle() {
        if (fixedLength) {
            pinCircles.get(pinPosition).setImageResource(R.drawable.hwsecurity_pin_circle_filled);
        } else {
            addPinCircleImageView(R.drawable.hwsecurity_pin_circle_filled);
        }
    }

    private void removePinCircle() {
        if (fixedLength) {
            pinCircles.get(pinPosition).setImageResource(R.drawable.hwsecurity_pin_circle);
        } else {
            removePinCircleImageView(pinCircles.get(pinPosition));
            setNumberButtonsEnabled(true);
        }
    }

    private void addPinCircleImageView(@DrawableRes int resId) {
        ImageView newCircle = new ImageView(context);
        newCircle.setImageResource(resId);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(convertDpToPx(CIRCLE_SIZE), convertDpToPx(CIRCLE_SIZE));
        lp.setMargins(convertDpToPx(CIRCLE_MARGIN_START), 0, 0, 0);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            lp.setMarginStart(convertDpToPx(CIRCLE_MARGIN_START));
        }
        newCircle.setLayoutParams(lp);
        pinCirclesLayout.addView(newCircle);

        pinCircles.add(newCircle);
    }

    private void removePinCircleImageView(ImageView circleView) {
        pinCirclesLayout.removeView(circleView);
        pinCircles.remove(circleView);
    }

    private int convertDpToPx(@SuppressWarnings("SameParameterValue") int dp) {
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        float pixels = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, dp, displayMetrics);
        return Math.round(pixels);
    }

    private ByteSecret getPinAndClear() {
        if (pinPosition == 0) {
            return null;
        } else {
            return ByteSecret.fromByteArrayAndClear(pin, pinPosition);
        }
    }

    @Override
    public void confirmPin() {
        callback.onPinEntered(getPinAndClear());
    }
}
