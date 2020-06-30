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

import android.app.Activity;
import android.content.Context;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;

import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;

import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.ui.R;

@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class KeyboardPinInput extends PinInput {
    private Context context;

    private View view;
    private EditText keyboardInput;

    private PinInputCallback callback;

    public void setPinInputCallback(PinInputCallback callback) {
        this.callback = callback;
    }

    public KeyboardPinInput(@NonNull View view) {
        this.context = view.getContext();
        this.keyboardInput = view.findViewById(R.id.keyboardInput);
        this.view = view;

        keyboardInput.setOnEditorActionListener((v, actionId, event) -> {
            // Associate the "done" button on the soft keyboard and the Enter Key (in case a hard keyboard is used)
            // with confirmPin
            if (EditorInfo.IME_ACTION_DONE == actionId ||
                    (actionId == EditorInfo.IME_ACTION_UNSPECIFIED &&
                            event.getAction() == KeyEvent.ACTION_DOWN &&
                            event.getKeyCode() == KeyEvent.KEYCODE_ENTER)) {
                confirmPin();
                return true;
            }
            return false;
        });

        view.findViewById(R.id.keyboardButtonConfirm).setOnClickListener(v -> confirmPin());
    }

    public void setVisibility(int visibility) {
        view.setVisibility(visibility);
    }

    public int getVisibility() {
        return view.getVisibility();
    }

    public void openKeyboard() {
        keyboardInput.setOnFocusChangeListener((v, hasFocus) -> keyboardInput.post(() -> {
            if (!hasFocus) {
                return;
            }
            if (context == null || keyboardInput == null) {
                return;
            }
            InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
            if (imm == null) {
                return;
            }
            imm.showSoftInput(keyboardInput, InputMethodManager.SHOW_IMPLICIT);
        }));
        keyboardInput.requestFocus();
    }

    private void closeKeyboard() {
        InputMethodManager imm = (InputMethodManager) context.getSystemService(Activity.INPUT_METHOD_SERVICE);
        if (imm == null) {
            return;
        }
        imm.hideSoftInputFromWindow(keyboardInput.getWindowToken(), 0);
        keyboardInput.clearFocus();
    }

    private ByteSecret getPinAndClear() {
        closeKeyboard();
        if (keyboardInput.length() == 0) {
            return null;
        } else {
            return ByteSecret.fromEditableAsUtf8AndClear(keyboardInput.getText());
        }
    }

    @Override
    public void confirmPin() {
        ByteSecret pinSecret = getPinAndClear();
        callback.onPinEntered(pinSecret);
    }
}
