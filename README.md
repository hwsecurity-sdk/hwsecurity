# Hardware Security SDK

An SDK for supporting security keys and smartcards on Android.
Use cases include:
* WebAuthn/FIDO2 passwordless logins
* FIDO U2F Two-Factor Authentication
* SSH Authentication using OpenPGP/PIV cards
* Personal Identity Verification (PIV)
* Full app database encryption using external hardware

## Documentation

Code examples and documentation can be found on our developer page at [hwsecurity.dev/docs](https://hwsecurity.dev/docs/).

## Open Source

This repository contains all parts of the Hardware Security SDK that have been released as open source.

This includes the following artifacts of the SDK (cf. [overview of all artifacts](https://hwsecurity.dev/docs/sdk/#sdk-artifacts)):

| Build Artifact                     | Min SDK | Rec. SDK |
|------------------------------------|---------|----------|
| de.cotech:hwsecurity               | 14      |          |
| de.cotech:hwsecurity-intent-nfc    | 14      |          |
| de.cotech:hwsecurity-intent-usb    | 14      |          |
| de.cotech:hwsecurity-fido          | 14      | 19       |
| de.cotech:hwsecurity-fido2         | 14      | 19       |
| de.cotech:hwsecurity-openpgp       | 14      |          |
| de.cotech:hwsecurity-piv           | 14      |          |
| de.cotech:hwsecurity-ui            | 14      | 19       |
| de.cotech:hwsecurity-ssh           | 14      |          |
| de.cotech:hwsecurity-sshj          | 14      |          |

## Notice

This open source release does not reflect the newest version of the SDK.
Some parts are currently not released as GPLv3.

## Maven/NuGet Repositories

For paying customers, we provide an official Maven and NuGet repository:
* [Documentation for Maven](https://hwsecurity.dev/docs/sdk/)
* [Documentation for NuGet](https://hwsecurity.dev/xamarin/xamarin-sdk/)

There is also an unofficial Maven repository for open source projects using the SDK under GPLv3:
* https://jitpack.io/#cotechde/hwsecurity/

## Contributing

Hardware Security SDK is an open source project and we are very happy to accept community contributions.

We will ask you to sign our [CLA](https://cla-assistant.io/cotechde/hwsecurity) before your pull request can be merged.

## Commercial License

A commercial license can be purchased on [hwsecurity.dev/sales](https://hwsecurity.dev/sales/).

Buying such a license is mandatory as soon as you develop commercial activities involving this program without disclosing the source code of your own applications.

You can use our SDK under the terms of the GNU General Public license version 3 or later.
