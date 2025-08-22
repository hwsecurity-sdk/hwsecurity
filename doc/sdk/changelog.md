+++
title = "Changelog"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight=70

# Add menu entry to sidebar.
linktitle = "Changelog"
[menu.docs]
  parent = "hw-security-docs"
  weight = 70

+++

Only important changes are noted here. Most versions incorporate a lot of other bugfixes.
The artifacts use strict [Semantic Versioning](https://semver.org/).

#### 4.4.0
* hwsecurity-sshj: new artifact for using the SSHJ library with OpenPGP and PIV security keys
* hwsecurity-openpgp: Curve25519 support in key generation and SSH
* updated dependencies:
  * androidx.lifecycle:lifecycle-runtime:2.3.0
  * androidx.appcompat:appcompat:1.2.0
  * androidx.constraintlayout:constraintlayout:2.0.4
  * com.google.android.material:material:1.3.0

#### 4.3.0
* hwsecurity-openpgp: ``OpenPgpSecurityKey.setupPairedKey()`` now allows to setup ECC keys
* hwsecurity-openpgp: add password KDF  as described in OpenPGP application specifications v3.3 chapter 4.3.2.
* hwsecurity-openpgp: fix ECDH decryption error using NIST curves: Invalid KEK
* hwsecurity-openpgp: add workaround for YubiKey firmware bug with ECC curves

#### 4.2.1
* org.bouncycastle:bcprov-jdk15on:1.65 (1.67 does not work with Jetifier)

#### 4.2.0
* hwsecurity-fido2: 'fido-u2f' backward compatibility fixes for Titan Key
* hwsecurity-ui: success state before dialog is dismissed
* org.bouncycastle:bcprov-jdk15on:1.67

#### 4.1.5
* hwsecurity-fido2: fix crash happening after ProGuard optimization

#### 4.1.4
* hwsecurity-fido2: improved handling of 0 remaining PIN retries

#### 4.1.3
* hwsecurity-fido2: fix backward compatibility with 'fido-u2f'
* hwsecurity-fido2: better error handling if FIDO2 is disabled or unsupported
* hwsecurity-fido: better error handling if U2F is disabled or unsupported
* hwsecurity: improved USB reconnecting behaviour
* hwsecurity: add support for Sentry logging

#### 4.1.2
* hwsecurity-fido2: compatibility fixes for FIDO2 PIN protocol. This provides support for Excelsecu FIDO2 security keys.

#### 4.1.1
* hwsecurity-fido2: fix public suffix check in rpId verification

#### 4.1.0
* hwsecurity: add configuration option to exclude activities from the ``SecurityKeyManager`` via ``addExcludedActivityClass()``

#### 4.0.8
* hwsecurity-fido2: fix crash on WebAuthn timeout
* hwsecurity-ui: update AndroidX dependencies

#### 4.0.7
* hwsecurity-fido2: do not allow empty PIN

#### 4.0.6
* hwsecurity-fido2: Xamarin build fixes

#### 4.0.5
* hwsecurity-fido2: follow Chrome's WebAuthn behaviour more closely

#### 4.0.4
* hwsecurity-fido2: improve compatibility with usernameless WebAuthn logins

#### 4.0.3
* hwsecurity-fido2: Xamarin build fixes

#### 4.0.2
* hwsecurity-fido2: dependency issues resolved
* hwsecurity-fido2: improved error handling when PIN is not set

#### 4.0.1
* hwsecurity-ui: show pinpad by default, not keyboard

#### 4.0.0

* hwsecurity-fido2: support for passwordless authentication
* hwsecurity-fido2: support for PINs
* hwsecurity-fido2: support for resident keys (username-less authentication)
* hwsecurity: compatibility fixes for short/extended length APDU handling. This provides support for HID Crescendo C2300.
* hwsecurity: ``ByteSecretGenerator`` has been moved from hwsecurity-openpgp to the core hwsecurity artifact
* hwsecurity: ``AndroidPreferenceSimplePinProvider`` has been moved from hwsecurity-openpgp to the core hwsecurity artifact
* hwsecurity-ui: ``SecurityKeyDialogFactory`` has been removed. Instead each hwsecurity artifact contains a specific dialog fragment:
  * replace ``SecurityKeyDialogFactory.newOpenPgpInstance()`` with ``OpenPgpSecurityKeyDialogFragment.newInstance()``
  * replace ``SecurityKeyDialogFactory.newPivInstance()`` with ``PivSecurityKeyDialogFragment.newInstance()``
* replace ``SecurityKeyManagerConfig.setEnableNfcTagMonitoring()`` with ``SecurityKeyManagerConfig.setEnablePersistentNfcConnection()``

#### 3.2.2

* hwsecurity-fido2: fix crash in WebViewWebauthnBridge

#### 3.2.1

* inter-dependency issue has been resolved

#### 3.2.0

* hwsecurity-ui: automatically proceed in NFC screen if PIN is provided
* hwsecurity-ui: increase maximum PIN size that can be entered in our PIN pad to 16 digits
* hwsecurity-ui: support hardware keyboards for PIN input
* hwsecurity-ui: update database of NFC sweetspots
* Initial FIDO2 support has been added: ``hwsecurity-fido2``. Currently, support is limited to two-factor authentication scenarios.

#### 3.1.0

* hwsecurity-piv: support for resetting the PIN
* hwsecurity-piv: better handling of PIN retries and PIN errors

#### 3.0.0

* SSH functionality has been refactored and moved into its own artifact: ``hwsecurity-ssh``
* removed deprecated classes and methods
* hwsecurity-piv: Support for SSH authentication

#### 2.5.1

* hwsecurity-ui: fix ``setTitle()``

#### 2.5.0

* hwsecurity: deprecated ``CharSecret``, please use ``ByteSecret`` for all use cases
* hwsecurity: NFC stability and responsiveness improved
* hwsecurity-openpgp: properly detect PIN exceptions for YubiKey NEO
* hwsecurity-ui: fix crashes on Android < 5
* hwsecurity-ui: new flow with ``PinMode.SETUP`` guiding the user through key generation
* hwsecurity-ui: display remaining PIN retries

#### 2.4.6

* hwsecurity-fido: add parameter to pass-through ``FidoDialogOptions`` to the ``WebViewFidoBridge``

#### 2.4.5

* hwsecurity-fido: option to set your own dialog theme

#### 2.4.4

* hwsecurity-ui: option to set your own dialog theme

#### 2.4.3

* hwsecurity: ignoring NFC tags is now an option and not enabled by default
* hwsecurity-ui: automatically remember PIN input

#### 2.4.2

* hwsecurity-ui: add security key icons for usage in apps
* hwsecurity-ui: always use vector drawables instead of pngs

#### 2.4.1

* hwsecurity-ui: ``SecurityKeyDialogFragment``: rename optional callback setter to ``setSecurityKeyDialogCallback``

#### 2.4.0

* hwsecurity: Removed timber dependency

#### 2.3.3

* hwsecurity-ui: Fix animation loops

#### 2.3.2

* hwsecurity-ui: Added animations for Security Keys (now default). You can choose your form factor shown in the dialog with ``SecurityKeyDialogOptions.builder().setFormFactor()``
* hwsecurity-ui: Now properly works with USB Security Keys that are already inserted when the dialog is shown

#### 2.3.1

* hwsecurity-ui: PIN input fallback mode using keyboard. Can be enabled using ``SecurityKeyDialogOptions.setAllowKeyboard(true)``

#### 2.3.0

* The new artifact ``de.cotech:hwsecurity-ui`` replaces the now deprecated ``de.cotech:hwsecurity-smartcard-ui``
* hwsecurity-openpgp: New methods ``OpenPgpSecurityKey.getSecurityKeyName()`` and ``OpenPgpSecurityKey.getSerialNumber()``

#### 2.2.4

* hwsecurity-fido: Call callbacks after timeout to properly show error
* hwsecurity-fido: Better support for smartphones that do not support APDU extended length properly

#### 2.2.3

* hwsecurity-fido: Fix integration when app theme does not inherit from Theme.MaterialComponents

#### 2.2.2

* hwsecurity-fido: Checks if NFC hardware is available and enabled and shows help if not
* hwsecurity: Support for SoloKey and SoloKey Tap over USB and NFC
* hwsecurity: Improved USB HID stability

#### 2.2.1

* hwsecurity-openpgp: Fixes applet selection when multiple AIDs are defined in ``OpenPgpSecurityKeyConnectionModeConfig``

#### 2.2.0

* smartcard-smartcard-ui: API changes, now with OpenPGP and PIV protocol

#### 2.1.0

* smartcard-smartcard-ui: New artifact implementing a UI for PIN input and PIN reset with a keypad
* smartcard-openpgp: Now throws Exceptions for errors according to the OpenPGP specification

#### 2.0.0

* Hardware Security SDK Version 2 release
* New API reference, documentation and guides on [https://hwsecurity.dev/](https://hwsecurity.dev/)
* All packages live in a consistent namespace starting with the string ``de.cotech.hw``
* The artifacts use strict [Semantic Versioning](https://semver.org/).
