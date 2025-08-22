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
