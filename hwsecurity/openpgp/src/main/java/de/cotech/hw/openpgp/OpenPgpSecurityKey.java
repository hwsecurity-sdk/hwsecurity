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

package de.cotech.hw.openpgp;


import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import androidx.annotation.WorkerThread;
import de.cotech.hw.SecurityKey;
import de.cotech.hw.SecurityKeyAuthenticator;
import de.cotech.hw.SecurityKeyException;
import de.cotech.hw.SecurityKeyManagerConfig;
import de.cotech.hw.internal.transport.SecurityKeyInfo;
import de.cotech.hw.internal.transport.Transport;
import de.cotech.hw.internal.transport.usb.UsbSecurityKeyTypes;
import de.cotech.hw.openpgp.exceptions.OpenPgpPublicKeyUnavailableException;
import de.cotech.hw.openpgp.internal.OpenPgpAppletConnection;
import de.cotech.hw.openpgp.internal.openpgp.KeyFormat;
import de.cotech.hw.openpgp.internal.openpgp.KeyType;
import de.cotech.hw.openpgp.internal.openpgp.OpenPgpAid;
import de.cotech.hw.openpgp.internal.operations.ChangeKeyRsaOp;
import de.cotech.hw.openpgp.internal.operations.ModifyPinOp;
import de.cotech.hw.openpgp.internal.operations.ResetAndWipeOp;
import de.cotech.hw.openpgp.pairedkey.PairedSecurityKey;
import de.cotech.hw.openpgp.util.RsaEncryptionUtil;
import de.cotech.hw.provider.CotechSecurityKeyProvider;
import de.cotech.hw.provider.SecurityKeyPrivateKey.SecurityKeyEcdsaPrivateKey;
import de.cotech.hw.provider.SecurityKeyPrivateKey.SecurityKeyRsaPrivateKey;
import de.cotech.hw.secrets.ByteSecret;
import de.cotech.hw.secrets.PinProvider;
import de.cotech.hw.util.HwTimber;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;


@SuppressWarnings({"WeakerAccess", "unused"}) // public API
public class OpenPgpSecurityKey extends SecurityKey {
    private static final ByteSecret DEFAULT_PUK = ByteSecret.unsafeFromString("12345678");

    public final OpenPgpAppletConnection openPgpAppletConnection;

    OpenPgpSecurityKey(SecurityKeyManagerConfig config, Transport transport,
                       OpenPgpAppletConnection openPgpAppletConnection) {
        super(config, transport);
        this.openPgpAppletConnection = openPgpAppletConnection;
    }

    /**
     * Retrieves a public key for the given KeyType.
     */
    @RestrictTo(Scope.LIBRARY_GROUP)
    @WorkerThread
    public PublicKey retrievePublicKey(KeyType keyType) throws IOException {
        byte[] publicKeyBytes = openPgpAppletConnection.retrievePublicKey(keyType.getSlot());
        KeyFormat keyFormat = openPgpAppletConnection.getOpenPgpCapabilities().getFormatForKeyType(keyType);
        return keyFormat.getKeyFormatParser().parseKey(publicKeyBytes);
    }

    /**
     * Returns true if the connected security key has never been set up.
     *
     * @see #setupPairedKey(PinProvider)
     */
    @AnyThread
    public boolean isSecurityKeyEmpty() {
        return !openPgpAppletConnection.getOpenPgpCapabilities().hasSignKey()
                && !openPgpAppletConnection.getOpenPgpCapabilities().hasEncryptKey()
                && !openPgpAppletConnection.getOpenPgpCapabilities().hasAuthKey();
    }

    /**
     * This method directly performs IO with the security token, and should therefore not be called on the UI thread.
     */
    @WorkerThread
    @RestrictTo(Scope.LIBRARY_GROUP)
    public void updatePinAndPukUsingDefaultPuk(ByteSecret newPin, ByteSecret newPuk) throws IOException {
        ModifyPinOp modifyPinOp = ModifyPinOp.create(openPgpAppletConnection);
        modifyPinOp.modifyPw1AndPw3(DEFAULT_PUK, newPin, newPuk);
    }

    /**
     * This method directly performs IO with the security token, and should therefore not be called on the UI thread.
     */
    @WorkerThread
    @RestrictTo(Scope.LIBRARY_GROUP)
    public void updatePinUsingPuk(ByteSecret currentPuk, ByteSecret newPin) throws IOException {
        ModifyPinOp modifyPinOp = ModifyPinOp.create(openPgpAppletConnection);
        modifyPinOp.modifyPw1Pin(currentPuk, newPin);
    }

    /**
     * Resets the security key into its factory state wiping all private keys, and authenticates for subsequent
     * administrative operations.
     *
     * <b>This is an internal method, it shouldn't be used by most apps.</b>
     * <p>
     * This method directly performs IO with the security token, and should therefore not be called on the UI thread.
     *
     * @see #setupPairedKey(PinProvider)
     */
    @WorkerThread
    @RestrictTo(Scope.LIBRARY_GROUP)
    public void wipeAndVerify() throws IOException {
        ResetAndWipeOp resetAndWipe = ResetAndWipeOp.create(openPgpAppletConnection);
        resetAndWipe.resetAndWipeSecurityKey();
        openPgpAppletConnection.verifyPuk(DEFAULT_PUK);
    }

    @WorkerThread
    private boolean isInFactoryDefaultState() throws IOException {
        if (isSecurityKeyEmpty()) {
            try {
                // make one attempt at entering the default PUK
                openPgpAppletConnection.verifyPuk(DEFAULT_PUK);
                return true;
            } catch (SecurityKeyException e) {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * This methods sets up the connected security key for signing, encryption, and authentication.
     *
     * <ol>
     * <li>Wipes current data on the security key</li>
     * <li>Generates a new key pair, storing the private pair on the security key</li>
     * <li>Returns a PairedSecurityKey with the info</li>
     * <li>Locks the security key with a pin, provided by the PinProvider parameter</li>
     * </ol>
     *
     * @see PairedSecurityKey
     * @see PinProvider
     * <p>
     * This method directly performs IO with the security token, and should therefore not be called on the UI thread.
     */
    @WorkerThread
    public PairedSecurityKey setupPairedKey(PinProvider pinProvider) throws IOException {
        ByteSecret pairedPin = pinProvider.getPin(getOpenPgpInstanceAid());
        ByteSecret pairedPuk = pinProvider.getPuk(getOpenPgpInstanceAid());
        return setupPairedKey(pairedPin, pairedPuk);
    }

    @WorkerThread
    public PairedSecurityKey setupPairedKey(ByteSecret newPin, ByteSecret newPuk) throws IOException {
        return setupPairedKey(newPin, newPuk, false);
    }

    @WorkerThread
    public PairedSecurityKey setupPairedKey(ByteSecret newPin, ByteSecret newPuk, boolean encryptionOnly) throws IOException {
        boolean isInFactoryDefaultState = isInFactoryDefaultState();
        if (!isInFactoryDefaultState) {
            wipeAndVerify();
        }

        try {
            Date timestamp = new Date();
            ChangeKeyRsaOp changeKeyRsaOp = ChangeKeyRsaOp.create(openPgpAppletConnection);

            // TODO: automatic selection of ECC, if card supports it!
            // EccEncryptionUtil eccEncryptionUtil = new EccEncryptionUtil();
            // KeyPair authKeyPair = eccEncryptionUtil.generateEcKeyPair(SECObjectIdentifiers.secp256r1);

            // ChangeKeyEccOp changeKeyEccOp = ChangeKeyEccOp.create(openPgpAppletConnection);
            // changeKeyEccOp.changeKey(KeyType.SIGN, "secp256r1", authKeyPair, timestamp);
            // changeKeyEccOp.changeKey(KeyType.ENCRYPT, "secp256r1", authKeyPair, timestamp);
            // changeKeyEccOp.changeKey(KeyType.AUTH, "secp256r1", authKeyPair, timestamp);

            RsaEncryptionUtil rsaEncryptUtil = new RsaEncryptionUtil();
            if (encryptionOnly) {
                KeyPair encryptionKeyPair = rsaEncryptUtil.generateRsa2048KeyPair();
                byte[] encryptFingerprint = changeKeyRsaOp.changeKey(KeyType.ENCRYPT, encryptionKeyPair, timestamp);

                updatePinAndPukUsingDefaultPuk(newPin, newPuk);

                openPgpAppletConnection.refreshConnectionCapabilities();

                return new PairedSecurityKey(getOpenPgpInstanceAid(),
                        encryptFingerprint, encryptionKeyPair.getPublic(),
                        null, null,
                        null, null
                );
            } else {
                KeyPair encryptionKeyPair = rsaEncryptUtil.generateRsa2048KeyPair();
                KeyPair signKeyPair = rsaEncryptUtil.generateRsa2048KeyPair();
                KeyPair authKeyPair = rsaEncryptUtil.generateRsa2048KeyPair();
                byte[] encryptFingerprint = changeKeyRsaOp.changeKey(KeyType.ENCRYPT, encryptionKeyPair, timestamp);
                byte[] signFingerprint = changeKeyRsaOp.changeKey(KeyType.SIGN, signKeyPair, timestamp);
                byte[] authFingerprint = changeKeyRsaOp.changeKey(KeyType.AUTH, authKeyPair, timestamp);
                updatePinAndPukUsingDefaultPuk(newPin, newPuk);

                openPgpAppletConnection.refreshConnectionCapabilities();

                return new PairedSecurityKey(getOpenPgpInstanceAid(),
                        encryptFingerprint, encryptionKeyPair.getPublic(),
                        signFingerprint, signKeyPair.getPublic(),
                        authFingerprint, authKeyPair.getPublic()
                );
            }
        } catch (Exception e) {
            HwTimber.e(e);
            return null;
        }
    }

    @NonNull
    @AnyThread
    public byte[] getOpenPgpInstanceAid() {
        return openPgpAppletConnection.getOpenPgpCapabilities().getAid();
    }

    @NonNull
    @AnyThread
    public String getSecurityKeyName() {
        String hardwareName = null;

        // get name from USB device info
        SecurityKeyInfo.SecurityKeyType securityKeyType = transport.getSecurityKeyTypeIfAvailable();
        if (securityKeyType != null) {
            hardwareName = UsbSecurityKeyTypes.getSecurityKeyName(securityKeyType);
        }
        // if not available, get name from OpenPGP AID
        if (hardwareName == null) {
            OpenPgpAid openPgpAid = openPgpAppletConnection.getOpenPgpCapabilities().getOpenPgpAid();
            hardwareName = openPgpAid.getSecurityKeyName();
        }
        if (hardwareName == null) {
            hardwareName = "Security Key";
        }
        return hardwareName;
    }

    @NonNull
    @AnyThread
    public String getSerialNumber() {
        OpenPgpAid openPgpAid = openPgpAppletConnection.getOpenPgpCapabilities().getOpenPgpAid();
        return openPgpAid.getSerialNumberString();
    }

    /**
     * This method reads the bytes from the "cardholder certificate" data object (DO 0x7F21) from the security key.
     */
    @WorkerThread
    public byte[] readCertificateData() throws IOException {
        return openPgpAppletConnection.getData(0x7F21);
    }

    /**
     * This method puts the given bytes on the security key as its "cardholder certificate" data object (DO 0x7F21)
     */
    @WorkerThread
    public void putCertificateData(byte[] data) throws IOException {
        int maxLength = openPgpAppletConnection.getOpenPgpCapabilities().getMaxCardholderCertLength();
        if (data.length > maxLength) {
            throw new IOException("Cardholder certificate data is longer than permitted!");
        }
        openPgpAppletConnection.putData(0x7F21, data);
    }

    @AnyThread
    public int getMaxCertificateDataLength() {
        return openPgpAppletConnection.getOpenPgpCapabilities().getMaxCardholderCertLength();
    }

    /**
     * Returns true if the connected security key matches the one referenced by the provided PairedSecurityKey.
     */
    @AnyThread
    public boolean matchesPairedSecurityKey(PairedSecurityKey pairedSecurityKey) {
        return Arrays.equals(openPgpAppletConnection.getOpenPgpCapabilities().getFingerprintEncrypt(), pairedSecurityKey.getEncryptFingerprint());
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    @AnyThread
    public PrivateKey getJcaPrivateKeyForAuthentication(PinProvider pinProvider) {
        if (!CotechSecurityKeyProvider.isInstalled()) {
            throw new IllegalStateException("CotechSecurityProvider must be installed to use JCA private key operations!");
        }

        SecurityKeyAuthenticator securityKeyAuthenticator = createSecurityKeyAuthenticator(pinProvider);
        switch (openPgpAppletConnection.getOpenPgpCapabilities().getAuthKeyFormat().keyFormatType()) {
            case RSAKeyFormatType:
                return new SecurityKeyRsaPrivateKey(securityKeyAuthenticator);
            case ECKeyFormatType:
                return new SecurityKeyEcdsaPrivateKey(securityKeyAuthenticator);
            default:
                throw new IllegalStateException("Authentication key format not supported for this operation!");
        }
    }

    @RestrictTo(Scope.LIBRARY_GROUP)
    public SecurityKeyAuthenticator createSecurityKeyAuthenticator(PinProvider pinProvider) {
        return new OpenPgpSecurityKeyAuthenticator(this, pinProvider);
    }

    @WorkerThread
    public PublicKey retrieveAuthenticationPublicKey() throws IOException {
        if (!openPgpAppletConnection.getOpenPgpCapabilities().hasAuthKey()) {
            throw new OpenPgpPublicKeyUnavailableException("No authentication key available!");
        }
        return retrievePublicKey(KeyType.AUTH);
    }
}
