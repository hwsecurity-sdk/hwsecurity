# Hardware Security SDK

An SDK for supporting security keys and smartcards on Android.
Use cases include:
* WebAuthn/FIDO2 passwordless logins
* FIDO U2F Two-Factor Authentication
* SSH Authentication using OpenPGP/PIV cards
* Personal Identity Verification (PIV)
* Full app database encryption using external hardware

## Documentation

### SDK
* [SDK Overview](doc/sdk/sdk.md)
* [SDK Configuration](doc/sdk/config.md)
* [Supported Hardware](doc/sdk/supported-hardware.md)
* [Start App on Hardware Discovery](doc/sdk/intent-filter.md)
* [Changelog](doc/sdk/changelog.md)

### Guides
* [FIDO2/WebAuthn - WebView Bridge](doc/guide/fido-webview.md)
* [FIDO2 / WebAuthn](doc/guide/fido2.md)
* [FIDO U2F](doc/guide/fido.md)
* [SSH Authentication with Jsch](doc/guide/jsch.md)
* [SSH Authentication with SSHJ](doc/guide/sshj.md)
* [PIV for TLS Client Certificates](doc/guide/tls.md)
* [Encrypting Secrets](doc/guide/encryption.md)
* [Encrypted Database](doc/guide/database.md)


> [!CAUTION]
> If you are using the Jitpack repo, use ``com.github.cotechde:hwsecurity`` instead of ``de.cotech:hwsecurity``!


## Open Source

This repository contains all parts of the Hardware Security SDK that have been released as open source.

This includes the following artifacts of the SDK:


| Build Artifact                                          | Min SDK | Rec. SDK |
|---------------------------------------------------------|---------|----------|
| com.github.cotechde:hwsecurity:hwsecurity               | 14      |          |
| com.github.cotechde:hwsecurity:hwsecurity-intent-nfc    | 14      |          |
| com.github.cotechde:hwsecurity:hwsecurity-intent-usb    | 14      |          |
| com.github.cotechde:hwsecurity:hwsecurity-fido          | 14      | 19       |
| com.github.cotechde:hwsecurity:hwsecurity-fido2         | 14      | 19       |
| com.github.cotechde:hwsecurity:hwsecurity-openpgp       | 14      |          |
| com.github.cotechde:hwsecurity:hwsecurity-piv           | 14      |          |
| com.github.cotechde:hwsecurity:hwsecurity-ui            | 14      | 19       |
| com.github.cotechde:hwsecurity:hwsecurity-ssh           | 14      |          |
| com.github.cotechde:hwsecurity:hwsecurity-sshj          | 14      |          |

## Maven

This is the repository for open source projects:
* https://jitpack.io/#cotechde/hwsecurity/

## License: GPLv3+

You can use our SDK under the terms of the GNU General Public license version 3 or later.

## Other license?

If you need a different license, write us: support@hwsecurity.dev

We may be willing to release it as Apache v2 under certain conditions.

## Missing parts?

Some parts of the SDK haven't been released as open source. If you are missing something, please let us know: support@hwsecurity.dev

# Xamarin

> WARNING: Xamarin hasn't been build for a long time. This part of the SDK has been released on request

Must happen on Windows (Xamarin does not work with Linux)

## Xamarin requirements

* Install Visual Studio : https://docs.microsoft.com/de-de/xamarin/android/get-started/installation/windows
* Download nuget.exe and put it in $PATH: https://www.nuget.org/downloads

## Xamarin build

1. Build Java SDK from this repo
2. Copy aar files to xamarin folders (core, fido, fido2, ui)
   - hwsecurity/core/build/outputs/aar/core-release.aar to xamarin/Hwsecurity/Jars/
   - hwsecurity/fido/build/outputs/aar/core-release.aar to xamarin/HwsecurityFido/Jars/
   - hwsecurity/fido2/build/outputs/aar/core-release.aar to xamarin/HwsecurityFido2/Jars/
   - hwsecurity/ui/build/outputs/aar/core-release.aar to xamarin/HwsecurityUi/Jars/
3. Delete all obj and bin folders and then rebuild Visual Studio project with "release" target in Visual Studio
4. Run on device to see if it crashes
5. Optional: Update AndroidX dependencies in nuspec files
6. Package and publish: In xamarin folder: execute with version number: ``.\nuget-pack.bat 4.1.0``
7. Verify using standalone sample
