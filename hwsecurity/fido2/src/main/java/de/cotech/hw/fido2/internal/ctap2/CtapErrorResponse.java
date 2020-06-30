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

package de.cotech.hw.fido2.internal.ctap2;


import com.google.auto.value.AutoValue;


@SuppressWarnings("unused")
@AutoValue
public abstract class CtapErrorResponse extends Ctap2Response {
    public static final byte CTAP2_OK = 0x00; // Indicates successful response.
    public static final byte CTAP1_ERR_SUCCESS = 0x00; // Same as CTAP2_OK
    public static final byte CTAP1_ERR_INVALID_COMMAND = 0x01; // The command is not a valid CTAP command.
    public static final byte CTAP1_ERR_INVALID_PARAMETER = 0x02; // The command included an invalid parameter.
    public static final byte CTAP1_ERR_INVALID_LENGTH = 0x03; // Invalid message or item length.
    public static final byte CTAP1_ERR_INVALID_SEQ = 0x04; // Invalid message sequencing.
    public static final byte CTAP1_ERR_TIMEOUT = 0x05; // Message timed out.
    public static final byte CTAP1_ERR_CHANNEL_BUSY = 0x06; // Channel busy.
    public static final byte CTAP1_ERR_LOCK_REQUIRED = 0x0A; // Command requires channel lock.
    public static final byte CTAP1_ERR_INVALID_CHANNEL = 0x0B; // Command not allowed on this cid.
    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11; // Invalid/unexpected CBOR error.
    public static final byte CTAP2_ERR_INVALID_CBOR = 0x12; // Error when parsing CBOR.
    public static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14; // Missing non-optional parameter.
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = 0x15; // Limit for number of items exceeded.
    public static final byte CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16; // Unsupported extension.
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19; // Valid credential found in the exclude list.
    public static final byte CTAP2_ERR_PROCESSING = 0x21; // Processing (Lengthy operation is in progress).
    public static final byte CTAP2_ERR_INVALID_CREDENTIAL = 0x22; // Credential not valid for the authenticator.
    public static final byte CTAP2_ERR_USER_ACTION_PENDING = 0x23; // Authentication is waiting for user interaction.
    public static final byte CTAP2_ERR_OPERATION_PENDING = 0x24; // Processing, lengthy operation is in progress.
    public static final byte CTAP2_ERR_NO_OPERATIONS = 0x25; // No request is pending.
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26; // Authenticator does not support requested algorithm.
    public static final byte CTAP2_ERR_OPERATION_DENIED = 0x27; // Not authorized for requested operation.
    public static final byte CTAP2_ERR_KEY_STORE_FULL = 0x28; // Internal key storage is full.
    public static final byte CTAP2_ERR_NOT_BUSY = 0x29; // Authenticator cannot cancel as it is not busy.
    public static final byte CTAP2_ERR_NO_OPERATION_PENDING = 0x2A; // No outstanding operations.
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B; // Unsupported option.
    public static final byte CTAP2_ERR_INVALID_OPTION = 0x2C; // Not a valid option for current operation.
    public static final byte CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D; // Pending keep alive was cancelled.
    public static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2E; // No valid credentials provided.
    public static final byte CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F; // Timeout waiting for user interaction.
    public static final byte CTAP2_ERR_NOT_ALLOWED = 0x30; // Continuation command, such as, authenticatorGetNextAssertion not allowed.
    public static final byte CTAP2_ERR_PIN_INVALID = 0x31; // PIN Invalid.
    public static final byte CTAP2_ERR_PIN_BLOCKED = 0x32; // PIN Blocked.
    public static final byte CTAP2_ERR_PIN_AUTH_INVALID = 0x33; // PIN authentication,pinAuth, verification failed.
    public static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34; // PIN authentication,pinAuth, blocked. Requires power recycle to reset.
    public static final byte CTAP2_ERR_PIN_NOT_SET = 0x35; // No PIN has been set.
    public static final byte CTAP2_ERR_PIN_REQUIRED = 0x36; // PIN is required for the selected operation.
    public static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37; // PIN policy violation. Currently only enforces minimum length.
    public static final byte CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38; // pinToken expired on authenticator.
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = 0x39; // Authenticator cannot handle this request due to memory constraints.
    public static final byte CTAP2_ERR_ACTION_TIMEOUT = 0x3A; // The current operation has timed out.
    public static final byte CTAP2_ERR_UP_REQUIRED = 0x3B; // User presence is required for the requested operation.
    public static final byte CTAP1_ERR_OTHER = 0x7F; // Other unspecified error.
    public static final byte CTAP2_ERR_SPEC_LAST = (byte) 0xDF; // CTAP 2 spec last error.

    private static final byte CTAP2_ERR_EXTENSION_FIRST = (byte) 0xE0; // Extension specific error.
    private static final byte CTAP2_ERR_EXTENSION_LAST = (byte) 0xEF; // Extension specific error.
    private static final byte CTAP2_ERR_VENDOR_FIRST = (byte) 0xF0; // Vendor specific error.
    private static final byte CTAP2_ERR_VENDOR_LAST = (byte) 0xFF; // Vendor specific error.

    public static CtapErrorResponse create(byte errorCode) {
        return new AutoValue_CtapErrorResponse(errorCode);
    }

    public abstract byte errorCode();

    String errorText() {
        return errorDescription() + " (code 0x" + Integer.toHexString(errorCode()) + ")";
    }

    private String errorDescription() {
        if (errorCode() >= CTAP2_ERR_EXTENSION_FIRST && errorCode() <= CTAP2_ERR_EXTENSION_LAST) {
            return "CTAP extension error";
        }
        if (errorCode() >= CTAP2_ERR_VENDOR_FIRST && errorCode() <= CTAP2_ERR_VENDOR_LAST) {
            return "CTAP vendor error";
        }
        switch (errorCode()) {
            case CTAP1_ERR_INVALID_COMMAND:
                return "The command is not a valid CTAP command.";
            case CTAP1_ERR_INVALID_PARAMETER:
                return "The command included an invalid parameter.";
            case CTAP1_ERR_INVALID_LENGTH:
                return "Invalid message or item length.";
            case CTAP1_ERR_INVALID_SEQ:
                return "Invalid message sequencing.";
            case CTAP1_ERR_TIMEOUT:
                return "Message timed out.";
            case CTAP1_ERR_CHANNEL_BUSY:
                return "Channel busy.";
            case CTAP1_ERR_LOCK_REQUIRED:
                return "Command requires channel lock.";
            case CTAP1_ERR_INVALID_CHANNEL:
                return "Command not allowed on this cid.";
            case CTAP2_ERR_CBOR_UNEXPECTED_TYPE:
                return "Invalid/unexpected CBOR error.";
            case CTAP2_ERR_INVALID_CBOR:
                return "Error when parsing CBOR.";
            case CTAP2_ERR_MISSING_PARAMETER:
                return "Missing non-optional parameter.";
            case CTAP2_ERR_LIMIT_EXCEEDED:
                return "Limit for number of items exceeded.";
            case CTAP2_ERR_UNSUPPORTED_EXTENSION:
                return "Unsupported extension.";
            case CTAP2_ERR_CREDENTIAL_EXCLUDED:
                return "Valid credential found in the exclude list.";
            case CTAP2_ERR_PROCESSING:
                return "Processing (Lengthy operation is in progress).";
            case CTAP2_ERR_INVALID_CREDENTIAL:
                return "Credential not valid for the authenticator.";
            case CTAP2_ERR_USER_ACTION_PENDING:
                return "Authentication is waiting for user interaction.";
            case CTAP2_ERR_OPERATION_PENDING:
                return "Processing, lengthy operation is in progress.";
            case CTAP2_ERR_NO_OPERATIONS:
                return "No request is pending.";
            case CTAP2_ERR_UNSUPPORTED_ALGORITHM:
                return "Authenticator does not support requested algorithm.";
            case CTAP2_ERR_OPERATION_DENIED:
                return "Not authorized for requested operation.";
            case CTAP2_ERR_KEY_STORE_FULL:
                return "Internal key storage is full.";
            case CTAP2_ERR_NOT_BUSY:
                return "Authenticator cannot cancel as it is not busy.";
            case CTAP2_ERR_NO_OPERATION_PENDING:
                return "No outstanding operations.";
            case CTAP2_ERR_UNSUPPORTED_OPTION:
                return "Unsupported option.";
            case CTAP2_ERR_INVALID_OPTION:
                return "Not a valid option for current operation.";
            case CTAP2_ERR_KEEPALIVE_CANCEL:
                return "Pending keep alive was cancelled.";
            case CTAP2_ERR_NO_CREDENTIALS:
                return "No valid credentials provided.";
            case CTAP2_ERR_USER_ACTION_TIMEOUT:
                return "Timeout waiting for user interaction.";
            case CTAP2_ERR_NOT_ALLOWED:
                return "Continuation command, such as, authenticatorGetNextAssertion not allowed.";
            case CTAP2_ERR_PIN_INVALID:
                return "PIN Invalid.";
            case CTAP2_ERR_PIN_BLOCKED:
                return "PIN Blocked.";
            case CTAP2_ERR_PIN_AUTH_INVALID:
                return "PIN authentication failed.";
            case CTAP2_ERR_PIN_AUTH_BLOCKED:
                return "PIN authentication blocked. Requires power recycle to reset.";
            case CTAP2_ERR_PIN_NOT_SET:
                return "No PIN has been set.";
            case CTAP2_ERR_PIN_REQUIRED:
                return "PIN is required for the selected operation.";
            case CTAP2_ERR_PIN_POLICY_VIOLATION:
                return "PIN policy violation. Currently only enforces minimum length.";
            case CTAP2_ERR_PIN_TOKEN_EXPIRED:
                return "pinToken expired on authenticator.";
            case CTAP2_ERR_REQUEST_TOO_LARGE:
                return "Authenticator cannot handle this request due to memory constraints.";
            case CTAP2_ERR_ACTION_TIMEOUT:
                return "The current operation has timed out.";
            case CTAP2_ERR_UP_REQUIRED:
                return "User presence is required for the requested operation.";
            case CTAP1_ERR_OTHER:
                return "Other unspecified error.";
            default:
                return "Unknown CTAP error";
        }
    }
}
