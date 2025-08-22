+++
title = "SDK Overview"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 1

# Add menu entry to sidebar.
linktitle = "SDK Overview"
[menu.docs]
  parent = "hw-security-docs"
  weight = 1
+++

With Cotech SDKs, your app can take advantage of the latest security solutions for authentication and end-to-end encryption.
SDK updates are distributed via our Maven repository.
This makes it easy for you to integrate the newest versions that we have to offer.

## Add the SDK to Your Project

To get a username and password for our Maven repository, please [contact us for a license]({{< ref "/sales/index.md" >}}).

Add this to your ``build.gradle``:

```gradle
repositories {
    google()
    jcenter()
    maven {
        credentials {
            username "xxx"
            password "xxx"
        }
        url "https://maven.cotech.de"
    }
}

dependencies {
    // Base artifact
    implementation 'de.cotech:hwsecurity:{{< hwsecurity-current-version >}}'

    // If included, the app will show up when a security key is connected via USB.
    implementation 'de.cotech:hwsecurity-intent-nfc:{{< hwsecurity-current-version >}}'
    // If included, the app will show up when a security key is held against the NFC sweetspot.
    implementation 'de.cotech:hwsecurity-intent-usb:{{< hwsecurity-current-version >}}'
    
    // FIDO2/WebAuthn implementation
    implementation 'de.cotech:hwsecurity-fido2:{{< hwsecurity-current-version >}}'
    
    // FIDO implementation
    implementation 'de.cotech:hwsecurity-fido:{{< hwsecurity-current-version >}}'

    // Additional classes for local parsing and verification of FIDO messages
    // Usually not required for FIDO clients.
    implementation 'de.cotech:hwsecurity-fido-util:{{< hwsecurity-current-version >}}'

    // To support OpenPGP Security Keys
    implementation 'de.cotech:hwsecurity-openpgp:{{< hwsecurity-current-version >}}'

    // To support PIV Security Keys
    implementation 'de.cotech:hwsecurity-piv:{{< hwsecurity-current-version >}}'

    // For TLS client certificate authentication (for example with PIV Security Keys)
    implementation 'de.cotech:hwsecurity-provider:{{< hwsecurity-current-version >}}'
    
    // For SSH with Jsch (with OpenPGP or PIV Security Keys)
    implementation 'de.cotech:hwsecurity-ssh:{{< hwsecurity-current-version >}}'
    
    // For SSH with SSHJ (with OpenPGP or PIV Security Keys)
    implementation 'de.cotech:hwsecurity-sshj:{{< hwsecurity-current-version >}}'
    
    // Generic security key dialog with a keypad for PIN input
    implementation 'de.cotech:hwsecurity-ui:{{< hwsecurity-current-version >}}'
}
```


## SDK Artifacts

* All packages in our Hardware Security SDK live in a consistent namespace starting with the string ``de.cotech.hw``.

* The artifacts use strict [Semantic Versioning](https://semver.org/).

* All artifacts have a minimum SDK Version of 14 (Android >= 4.0). Though, we recommend a higher SDK (Rec. SDK) for some artifacts.

* All SDK artifacts are kept as small as possible with a minimum set of dependencies.

* ``hwsecurity-fido-util`` and ``hwsecurity-openpgp`` automatically provide a Proguard file via [``consumerProguardFiles``](https://developer.android.com/studio/projects/android-library#Considerations). When you set [``minifyEnabled true``](https://developer.android.com/studio/build/shrink-code) for your app, our Proguard file will automatically be used to remove unnecessary Bouncy Castle classes.


| Build Artifact                     | Version                            | Min SDK | Rec. SDK | Size     |
|------------------------------------|------------------------------------|---------|----------|----------|
| de.cotech:hwsecurity               | {{< hwsecurity-current-version >}} | 14      |          | ~158 KiB |
| de.cotech:hwsecurity-intent-nfc    | {{< hwsecurity-current-version >}} | 14      |          | ~2 KiB   |
| de.cotech:hwsecurity-intent-usb    | {{< hwsecurity-current-version >}} | 14      |          | ~2 KiB   |
| de.cotech:hwsecurity-fido2         | {{< hwsecurity-current-version >}} | 14      | 19       | ~360 KiB |
| de.cotech:hwsecurity-fido          | {{< hwsecurity-current-version >}} | 14      | 19       | ~128 KiB |
| de.cotech:hwsecurity-fido-util     | {{< hwsecurity-current-version >}} | 14      | 19       | ~45 KiB  |
| de.cotech:hwsecurity-openpgp       | {{< hwsecurity-current-version >}} | 14      |          | ~162 KiB |
| de.cotech:hwsecurity-piv           | {{< hwsecurity-current-version >}} | 14      |          | ~58 KiB  |
| de.cotech:hwsecurity-provider      | {{< hwsecurity-current-version >}} | 14      |          | ~10 KiB  |
| de.cotech:hwsecurity-ssh           | {{< hwsecurity-current-version >}} | 14      |          | ~8 KiB   |
| de.cotech:hwsecurity-sshj          | {{< hwsecurity-current-version >}} | 14      |          | ~5 KiB   |
| de.cotech:hwsecurity-ui            | {{< hwsecurity-current-version >}} | 14      | 19       | ~131 KiB |

## Dependencies

We strive to keep the number of external dependencies as small as possible.
When possible we use Android's API, e.g., for JSON parsing or JCA operations.
All artifacts depend on the core artifact ``de.cotech:hwsecurity``.

| Build Artifact                     |  Dependencies            |
|------------------------------------|--------------------------|
| de.cotech:hwsecurity               | androidx.lifecycle:lifecycle-runtime:2.3.0 |
| de.cotech:hwsecurity-intent-nfc    |                          |
| de.cotech:hwsecurity-intent-usb    |                          |
| de.cotech:hwsecurity-fido2         | de.cotech:hwsecurity-ui <br> androidx.appcompat:appcompat:1.2.0 <br> com.google.android.material:material:1.3.0 <br> androidx.constraintlayout:constraintlayout:2.0.4 |
| de.cotech:hwsecurity-fido          | de.cotech:hwsecurity-ui <br> androidx.appcompat:appcompat:1.2.0 <br> com.google.android.material:material:1.3.0 <br> androidx.constraintlayout:constraintlayout:2.0.4 |
| de.cotech:hwsecurity-fido-util     | de.cotech:hwsecurity-fido <br> org.bouncycastle:bcprov-jdk15on:1.65 |
| de.cotech:hwsecurity-openpgp       | org.bouncycastle:bcprov-jdk15on:1.65 |
| de.cotech:hwsecurity-piv           | de.cotech:hwsecurity-provider                         |
| de.cotech:hwsecurity-provider      |                          |
| de.cotech:hwsecurity-ssh           | org.bouncycastle:bcprov-jdk15on:1.65 |
| de.cotech:hwsecurity-sshj          | com.hierynomus:sshj:0.31.0 <br> org.bouncycastle:bcprov-jdk15on:1.65 |
| de.cotech:hwsecurity-ui            | androidx.appcompat:appcompat:1.2.0 <br> com.google.android.material:material:1.3.0 <br> androidx.constraintlayout:constraintlayout:2.0.4 |

### Dependency Licenses

The Hardware Security SDK uses code from other projects.
In order to comply with its license requirements we prepared a license text that can be included in your published app: [License Text]({{< ref "licenses.md" >}}).


