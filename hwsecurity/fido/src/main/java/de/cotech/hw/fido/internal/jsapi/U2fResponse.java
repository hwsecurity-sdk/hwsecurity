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

package de.cotech.hw.fido.internal.jsapi;


import androidx.annotation.Nullable;

import com.google.auto.value.AutoValue;

import java.nio.charset.Charset;


@AutoValue
public abstract class U2fResponse {
    private static final String REGISTER_RESPONSE_TYPE = "u2f_register_response";
    private static final String AUTHENTICATE_RESPONSE_TYPE = "u2f_sign_response";
    private static final String REGISTER_RESPONSE_VERSION = "U2F_V2";


    public abstract String type();
    public abstract ResponseData responseData();
    @Nullable
    public abstract Long requestId();


    public static U2fResponse createRegisterResponse(Long requestId, String clientData, byte[] registrationData) {
        RegisterResponseData responseData = new AutoValue_U2fResponse_RegisterResponseData(
                REGISTER_RESPONSE_VERSION, registrationData, clientData.getBytes(Charset.forName("UTF-8"))
        );

        return new AutoValue_U2fResponse(REGISTER_RESPONSE_TYPE, responseData, requestId);
    }

    public static U2fResponse createAuthenticateResponse(Long requestId, String clientData,
            byte[] keyHandle, byte[] signatureData) {
        SignResponseData reseponseData = new AutoValue_U2fResponse_SignResponseData(
                keyHandle, signatureData, clientData.getBytes(Charset.forName("UTF-8"))
        );

        return new AutoValue_U2fResponse(AUTHENTICATE_RESPONSE_TYPE, reseponseData, requestId);
    }

    public static U2fResponse createErrorResponse(String type, Long requestId, ErrorCode errorCode) {
        ErrorResponseData responseData = new AutoValue_U2fResponse_ErrorResponseData(errorCode, null);
        return new AutoValue_U2fResponse(type, responseData, requestId);
    }


    abstract static class ResponseData { }

    @AutoValue
    public abstract static class RegisterResponseData extends ResponseData {
        public abstract String version();
        @SuppressWarnings("mutable")
        public abstract byte[] registrationData();
        @SuppressWarnings("mutable")
        public abstract byte[] clientData();
    }

    @AutoValue
    public abstract static class SignResponseData extends ResponseData {
        @SuppressWarnings("mutable")
        public abstract byte[] keyHandle();
        @SuppressWarnings("mutable")
        public abstract byte[] signatureData();
        @SuppressWarnings("mutable")
        public abstract byte[] clientData();
    }

    @AutoValue
    public abstract static class ErrorResponseData extends ResponseData {
        public abstract ErrorCode errorCode();
        @Nullable
        public abstract String errorMessage();
    }

    @SuppressWarnings("unused") // complete API
    public enum ErrorCode {
        OK(0),
        OTHER_ERROR(1),
        BAD_REQUEST(2),
        CONFIGURATION_UNSUPPORTED(3),
        DEVICE_INELIGIBLE(4),
        TIMEOUT(5);

        public int value;

        ErrorCode(int value) {
            this.value = value;
        }
    }

}
