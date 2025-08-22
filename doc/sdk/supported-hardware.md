+++
title = "Supported Hardware"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 10

# Add menu entry to sidebar.
linktitle = "Supported Hardware"
[menu.docs]
  parent = "hw-security-docs"
  weight = 10

+++

Click the product name inside the table to show more details.

● : Feature supported by hardware and fully supported by our SDK  
◐ : Feature supported by hardware but not supported by our SDK ([contact us]({{< ref "/sales/index.md" >}}) for support)  
○ : Feature not supported by hardware

<table>
<thead>
<tr>
<th></th>
<th>FIDO2 <br> (Passwordless)</th>
<th>FIDO U2F <br> (Two-factor)</th>
<th>PIV <br> (SSH, TLS)</th>
<th>OpenPGP Card <br> (SSH, Encrypt)</th>
<th>NFC</th>
<th>USB</th>
</tr>
</thead>
<tbody>

{{% hardware-row slug="atoscardos" name="Atos CardOS DI v5.3 FIDO2"
    fido2="true" u2f="false" piv="false" openpgp="false" nfc="true" usb="○" %}}
    
Hardware Security SDK Notes
: Only FIDO2 support has been tested

{{% /hardware-row %}}

{{% hardware-row slug="cotechcard" name="Cotech Card"
    fido2="false" u2f="false" piv="true" openpgp="true" nfc="true" usb="○" %}}
At Cotech, we specifically choose a card vendor and develop a firmware for your purpose and cryptographic requirements.

OpenPGP Card algorithms
: RSA 4096, ECDSA/ECDH (NIST P-256, NIST P-384, NIST P-521, brainpool p256r1, brainpool p384r1, brainpool p512r1)
{{% /hardware-row %}}

{{% hardware-row slug="cryptnox" name="Cryptnox FIDO 2 Card"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="true" usb="○" %}}

Web
: https://www.cryptnox.com
{{% /hardware-row %}}

{{% hardware-row slug="esecu-fido2" name="Excelsecu eSecu FIDO2 Pro"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="true" usb="OTG¹" %}}
NFC works, but the antenna strengh is very low.

USB (vendor: 1ea8, product: fc25)

Web
: https://www.excelsecu.com/productdetail/esecufido2secu.html
{{% /hardware-row %}}


{{% hardware-row slug="esecu-fido2-nfc" name="Excelsecu eSecu FIDO2 NFC"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="true" usb="OTG¹" %}}
NFC works, but the antenna strengh is very low.

USB (vendor: 1ea8, product: fc25)

Web
: https://www.excelsecu.com/productdetail/esecufido2secu.html
{{% /hardware-row %}}


{{% hardware-row slug="esecu-fido2-fingerprint" name="Excelsecu eSecu FIDO2 Fingerprint Key"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}

Hardware Security SDK Notes
: Please contact us if you like to use biometric fingerprint verification. This is currently not implemented in the SDK.

USB (vendor: 1ea8, product: fc26)

Web
: https://www.excelsecu.com/productdetail/esecufido2secu.html
{{% /hardware-row %}}


{{% hardware-row slug="feitian-fido" name="Feitian ePass FIDO"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}

Web
: https://www.ftsafe.com/Products/FIDO/Single_Button_FIDO
{{% /hardware-row %}}


{{% hardware-row slug="feitian-fido-nfc" name="Feitian ePass FIDO-NFC"
    fido2="true" u2f="true" piv="true" openpgp="false" nfc="true" usb="OTG¹" %}}

PIV supported must be requested on purchase!

Web
: https://www.ftsafe.com/Products/FIDO/NFC
{{% /hardware-row %}}


{{% hardware-row slug="feitian-multipass-fido" name="Feitian MultiPass FIDO"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="true" usb="USB-C" %}}

Web
: https://www.ftsafe.com/Products/FIDO/Multi
{{% /hardware-row %}}


{{% hardware-row slug="feitian-biopass-fido" name="Feitian BioPass FIDO2"
    fido2="true" u2f="false" piv="false" openpgp="false" nfc="true" usb="USB-C" %}}

Web
: https://www.ftsafe.com/Products/FIDO/Bio
{{% /hardware-row %}}


{{% hardware-row slug="gnuk" name="Gnuk"
    fido2="false" u2f="false" piv="false" openpgp="true" nfc="false" usb="OTG¹" %}}
Gnuk is a free software implementation of an USB cryptographic token for GnuPG.

Hardware Security SDK Notes
: OpenPGP key generation only supported with Gnuk >= 1.2.5

OpenPGP Card algorithms
: RSA 2048 (RSA 4096 is too slow), EdDSA, ECDSA (NIST P-256, secp256k1), ECDH (X25519, NIST P-256, secp256k1)

Web
: https://www.fsij.org/gnuk/

Source Code
: http://git.gniibe.org/gitweb/?p=gnuk/gnuk.git
{{% /hardware-row %}}


{{% hardware-row slug="google-nfc" name="Google Titan Key"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="true" usb="OTG¹" %}}

* Hardware revision is printed on the back: T1, T2, T3, …
* NFC does not work prior to revision T3
* Revision T1 of the BLE Titan Security Key revision is [vulnerable](https://security.googleblog.com/2019/05/titan-keys-update.html)


Web
: https://cloud.google.com/titan-security-key
{{% /hardware-row %}}


{{% hardware-row slug="hid-c2300" name="HID Crescendo C2300"
    fido2="true" u2f="false" piv="half" openpgp="false" nfc="true" usb="○" %}}

Hardware Security SDK Notes
: Only FIDO2 support has been tested

Web
: https://www.hidglobal.de/products/cards-and-credentials/crescendo/c2300
{{% /hardware-row %}}


{{% hardware-row slug="keyid" name="Key ID"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}

Web
: https://www.key-id.com
{{% /hardware-row %}}


{{% hardware-row slug="nanos" name="Ledger Nano S"
    fido2="false" u2f="true" piv="false" openpgp="true" nfc="false" usb="OTG¹" %}}
Ledger Nano S is a cryptocurrency wallet that also allows cryptographic operations for other purposes.

Hardware Security SDK Notes
: Currently buggy FIDO U2F support, OpenPGP card key generation not supported

OpenPGP Card algorithms
: RSA 4096, EdDSA, ECDSA (secp256k1, secp256r1, brainpool 256r1 and brainpool 256t1 curves), ECDH (secp256k1, secp256r1, brainpool 256r1, brainpool 256t1 and curve25519 curves)

Web
: https://www.ledger.com/products/ledger-nano-s

Source Code
: https://github.com/LedgerHQ/blue-app-openpgp-card
{{% /hardware-row %}}


{{% hardware-row slug="nitrokeystart" name="Nitrokey Start"
    fido2="false" u2f="false" piv="false" openpgp="true" nfc="false" usb="OTG¹" %}}
Nitrokey Start is a commercial version of the Gnuk token.

OpenPGP Card algorithms
: RSA 2048 (RSA 4096 takes 8 seconds), EdDSA, ECDSA (NIST P-256, secp256k1), ECDH (X25519, NIST P-256, secp256k1)

Web
: https://www.nitrokey.com

Source Code
: https://github.com/Nitrokey/nitrokey-start-firmware
{{% /hardware-row %}}


{{% hardware-row slug="nitrokeypro" name="Nitrokey Pro"
    fido2="false" u2f="false" piv="false" openpgp="true" nfc="false" usb="OTG¹" %}}
Nitrokey Pro

OpenPGP Card algorithms
: RSA 2048

Web
: https://www.nitrokey.com

{{% /hardware-row %}}


{{% hardware-row slug="nitrokeystorage" name="Nitrokey Storage"
    fido2="false" u2f="false" piv="false" openpgp="true" nfc="false" usb="OTG¹" %}}
Nitrokey Storage

OpenPGP Card algorithms
: RSA 2048 ?

Web
: https://www.nitrokey.com

{{% /hardware-row %}}


{{% hardware-row slug="nitrokeyu2f" name="Nitrokey FIDO U2F"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
Nitrokey FIDO U2F

Web
: https://www.nitrokey.com
{{% /hardware-row %}}


{{% hardware-row slug="onlykey" name="OnlyKey"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
A Security Key with a hardware PIN pad.

Web
: https://onlykey.io
{{% /hardware-row %}}


{{% hardware-row slug="secalot" name="Secalot"
    fido2="false" u2f="true" piv="false" openpgp="true" nfc="false" usb="OTG¹" %}}

OpenPGP Card algorithms
: RSA 2048 ?

Web
: https://www.secalot.com

Source Code
: https://github.com/secalot
{{% /hardware-row %}}


{{% hardware-row slug="solokey" name="SoloKey"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="false" usb="USB-C / OTG¹" %}}
SoloKey

Web
: https://solokeys.com
{{% /hardware-row %}}


{{% hardware-row slug="solokeytap" name="SoloKey Tap"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="true" usb="USB-C / OTG¹" %}}
SoloKey Tap

Web
: https://solokeys.com
{{% /hardware-row %}}


{{% hardware-row slug="thetis-fido2" name="Thetis FIDO2 Security Key"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
Re-branded Excelsecu FIDO2 key.

Web
: https://thetis.io/collections/fido2
{{% /hardware-row %}}


{{% hardware-row slug="trezorone" name="Trezor One"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
Trezor One is a cryptocurrency wallet that also allows cryptographic operations for other purposes.

Not OpenPGP Card Spec compatible

U2F Counter is restored automatically on [firmwares 1.4.2 or higher](https://wiki.trezor.io/U2F#Restoring_U2F_Counter_on_Trezor).

Web
: https://trezor.io
{{% /hardware-row %}}


{{% hardware-row slug="trezort" name="Trezor Model T"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
Terzor Model T is a cryptocurrency wallet that also allows cryptographic operations for other purposes.

Web
: https://trezor.io
{{% /hardware-row %}}


{{% hardware-row slug="vivokey" name="VivoKey Apex"
    fido2="true" u2f="true" piv="false" openpgp="true" nfc="true" usb="○" %}}
VivoKey is an implanatable NFC chip. It's still unreleased.

Web
: https://www.vivokey.com/apex
{{% /hardware-row %}}


{{% hardware-row slug="yubikeyneo" name="YubiKey NEO"
    fido2="false" u2f="true" piv="true" openpgp="true" nfc="true" usb="OTG¹" %}}
YubiKey NEO

OpenPGP Card algorithms
: RSA 2048

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/

Source Code
: https://github.com/Yubico/ykneo-openpgp
{{% /hardware-row %}}


{{% hardware-row slug="yubikey4" name="YubiKey 4"
    fido2="false" u2f="true" piv="true" openpgp="true" nfc="false" usb="OTG¹" %}}
YubiKey 4

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey4n" name="YubiKey 4 Nano"
    fido2="false" u2f="true" piv="true" openpgp="true" nfc="false" usb="OTG¹" %}}
YubiKey 4 Nano

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey4c" name="YubiKey 4C"
    fido2="false" u2f="true" piv="true" openpgp="true" nfc="false" usb="USB-C" %}}
YubiKey 4C

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey4cn" name="YubiKey 4C Nano"
    fido2="false" u2f="true" piv="true" openpgp="true" nfc="false" usb="USB-C" %}}
YubiKey 4C Nano

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey5nfc" name="YubiKey 5 NFC"
    fido2="true" u2f="true" piv="true" openpgp="true" nfc="true" usb="OTG¹" %}}
YubiKey 5 NFC

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Since firmware 5.2.3: secp256r1, secp256k1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, curve25519

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey5n" name="YubiKey 5 Nano"
    fido2="true" u2f="true" piv="true" openpgp="true" nfc="false" usb="OTG¹" %}}
YubiKey 5 Nano

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Since firmware 5.2.3: secp256r1, secp256k1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, curve25519

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey5c" name="YubiKey 5C"
    fido2="true" u2f="true" piv="true" openpgp="true" nfc="false" usb="USB-C" %}}
YubiKey 5C

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Since firmware 5.2.3: secp256r1, secp256k1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, curve25519

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubikey5cn" name="YubiKey 5C Nano"
    fido2="true" u2f="true" piv="true" openpgp="true" nfc="false" usb="USB-C" %}}
YubiKey 5C Nano

OpenPGP Card algorithms
: RSA 2048, RSA 4096

Since firmware 5.2.3: secp256r1, secp256k1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, curve25519

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubicou2f" name="Yubico Security Key"
    fido2="false" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
Yubico Security Key

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubicofido2" name="Yubico Security Key 2"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="false" usb="OTG¹" %}}
Yubico Security Key 2

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


{{% hardware-row slug="yubicofido2nfc" name="Yubico Security Key 2 NFC"
    fido2="true" u2f="true" piv="false" openpgp="false" nfc="true" usb="OTG¹" %}}
Yubico Security Key 2 NFC

Web
: https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/
{{% /hardware-row %}}


</tbody>
</table>

-------------

1. [USB On-The-Go (OTG) adapter](https://en.wikipedia.org/wiki/USB_On-The-Go) can be used to connect USB-A security keys to USB micro or USB-C smartphones. 


{{< figure library="1" src="security-keys-home.png" title="A lot of different form factors are supported by the Hardware Security SDK." >}}

## Does it Support External NFC/Smartcard Reader?
In theory, the SDK can be configured to use external NFC/smartcard readers connected via USB to the phone.
As this is a niche use case, only a small number of readers are officially supported.
Please contact us, if you plan to use this feature.

Tested readers:

* ACS ACR1252 (contactless, recommended)
* SCM Microsystems Inc. SCR 3310 (contact)
* Gemalto Prox DU (contact + contactless)

## Hardware Missing?

If you need support for hardware that is currently missing from this page, please [contact us]({{< ref "/sales/index.md" >}}).

