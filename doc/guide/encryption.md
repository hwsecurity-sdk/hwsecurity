+++
title = "Encrypting Secrets"
draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 6

# Add menu entry to sidebar.
linktitle = "Encrypting Secrets"
[menu.docs]
  parent = "hw-security"
  weight = 6
+++

In this Encryption Guide, you learn how to integrate the SDK in your app, pair with a Security Key, and use it for data encryption.


## Add the SDK to Your Project

To get a username and password for our Maven repository, please [contact us for a license]({{< ref "/sales/index.md" >}}).

Add this to your ``build.gradle``:

```gradle
repositories {
    google()
    jcenter()
    maven {
        credentials {
            username 'xxx'
            password 'xxx'
        }
        url "https://maven.cotech.de"
    }
}

dependencies {
    implementation 'de.cotech:hwsecurity-openpgp:{{< hwsecurity-current-version >}}'
}
```

## Initialize the Hardware Security SDK

To use the SDK's functionality in your app, you need to initialize the ``SecurityKeyManager`` first.
This is the central class of the SDK, which dispatches incoming NFC and USB connections.
Perform this initialization in the ``onCreate`` method of your ``Application`` subclass.
This ensures Security Keys are reliably dispatched by your app while in the foreground.

We start by creating a new class which extends ``android.app.Application`` as follows:

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public class MyCustomApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        SecurityKeyManager securityKeyManager = SecurityKeyManager.getInstance();
        SecurityKeyManagerConfig config = new SecurityKeyManagerConfig.Builder()
            .setEnableDebugLogging(BuildConfig.DEBUG)
            .build();
        securityKeyManager.init(this, config);
    }
}
```
{{% /code-tab %}}
{{% code-tab "Kotlin" %}}
```kotlin
class MyCustomApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        val securityKeyManager = SecurityKeyManager.getInstance()
        val config = SecurityKeyManagerConfig.Builder()
            .setEnableDebugLogging(BuildConfig.DEBUG)
            .build()
        securityKeyManager.init(this, config)
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

Then, register your ``MyCustomApplication`` in your ``AndroidManifest.xml``:

```xml
<application 
    android:name=".MyCustomApplication"
    android:label="@string/app_name" 
...>
```

## Pairing Security Keys

Before it can be used for encryption, a Security Key must be set up.
To do this, call ``setupPairedKey`` on the ``OpenPgpSecurityKey``.
This method generates the necessary keys, and protects the card with a PIN code.

This procedure requires user interaction, e.g., the user needs to keep NFC-capable Security Keys at the phone's back.
Thus, it should be implemented in an Activity that is part of your app's first time/registration procedure.

For this example,  ``AndroidPreferenceSimplePinProvider`` is used, which generates a random PIN code and stores it in your app.
This way, no other app can communicate with the Security Key after setup, effectively pairing it with your app.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public class SetupActivity extends AppCompatActivity implements SecurityKeyCallback<OpenPgpSecurityKey> {
    private PinProvider pinProvider;
    private PairedSecurityKeyStorage pairedSecurityKeyStorage;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SecurityKeyManager.getInstance().registerCallback(
                OpenPgpSecurityKeyConnectionMode.getInstance(), this, this);
        pinProvider =
                AndroidPreferenceSimplePinProvider.getInstance(getApplicationContext());
        pairedSecurityKeyStorage =
                AndroidPreferencePairedSecurityKeyStorage.getInstance(getApplicationContext());
    }

    @Override
    public void onSecurityKeyDiscovered(OpenPgpSecurityKey securityKey) {
        // OpenPgpSecurityKey operations are blocking, consider executing them in a new thread
        PairedSecurityKey pairedSecurityKey = securityKey.setupPairedKey(pinProvider);
        // Store the pairedSecurityKey. That way we can use it for encryption at any point
        pairedSecurityKeyStorage.addPairedSecurityKey(pairedSecurityKey);
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Using Secrets instead of Passwords

{{% alert warning %}}
Security Keys themselves are not directly used to encrypt full files or databases.

Instead, they decrypt short secrets, that are in turn used to encrypt data.
{{% /alert %}}

When you would normally use a user-chosen password/passphrase to encrypt data, you now generate a random secret with the SDK's ``SecretGenerator``.
This secret is used for in-app data encryption, while the secret itself is encrypted to the Security Key.
Thus, the physical Security Key replaces user-chosen passwords.


{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public ByteSecret generateSecret() {
    SecretGenerator secretGenerator = SecretGenerator.getInstance();
    ByteSecret secret = secretGenerator.createRandom(32);

    // use returned secret for data encryption in-app
    return secret;
}
```
{{% /code-tab %}}
{{% code-tab "Kotlin" %}}
```kotlin
fun generateSecret(): ByteSecret {
    val secretGenerator = SecretGenerator.getInstance()
    val secret = secretGenerator.createRandom(32)

    // use returned secret for data encryption in-app
    return secret
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Encrypt to Security Keys
When the Security Key is paired and available as a ``PairedSecurityKey``, the generated secret can be encrypted.
Encrypting secrets "to a Security Key" can be done anywhere in your app.
Usually, it is done once during setup.
For encryption, it is **NOT** required that Security Key is connected to the device.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public byte[] encryptToSecurityKey(ByteSecret secret) {
    PairedSecurityKeyStorage pairedSecurityKeyStorage =
            AndroidPreferencePairedSecurityKeyStorage.getInstance(getApplicationContext());

    // for simplicity, we assume a single paired security key
    PairedSecurityKey pairedSecurityKey =
            pairedSecurityKeyStorage.getAllPairedSecurityKeys().iterator().next();

    byte[] encryptedSecret = new PairedEncryptor(pairedSecurityKey).encrypt(secret);

    return encryptedSecret;
}
```
{{% /code-tab %}}
{{% code-tab "Kotlin" %}}
```kotlin
fun encryptToSecurityKey(secret: ByteSecret): ByteArray {
    val pairedSecurityKeyStorage =
            AndroidPreferencePairedSecurityKeyStorage.getInstance(getApplicationContext())

    // for simplicity, we assume a single paired security key
    val pairedSecurityKey =
            pairedSecurityKeyStorage.getAllPairedSecurityKeys().firstOrNull()

    val encryptedSecret = PairedEncryptor(pairedSecurityKey).encrypt(secret)

    return encryptedSecret
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Storing and Retrieving Encrypted Secrets
The SDK offers utilities for persisting the ``encryptedSecret``.
In this basic guide, we store it in an Android preference XML file using the Security Key's Application Identifier (AID) for later retrieval.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
private void saveEncryptedSecret(PairedSecurityKey pairedSecurityKey, byte[] encryptedSecret) {
    EncryptedSessionStorage encryptedSessionStorage =
            AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext());
    encryptedSessionStorage.setEncryptedSessionSecret(
            pairedSecurityKey.getSecurityKeyAid(), encryptedSecret);
}

private byte[] getEncryptedSecret(PairedSecurityKey pairedSecurityKey) {
    EncryptedSessionStorage encryptedSessionStorage =
            AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext());
    return encryptedSessionStorage.getEncryptedSessionSecret(pairedSecurityKey.getSecurityKeyAid());
}
```
{{% /code-tab %}}
{{% code-tab "Kotlin" %}}
```kotlin
private fun saveEncryptedSecret(pairedSecurityKey: PairedSecurityKey, encryptedSecret: ByteArray) {
    val encryptedSessionStorage =
            AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext())
    encryptedSessionStorage.setEncryptedSessionSecret(
            pairedSecurityKey.getSecurityKeyAid(), encryptedSecret)
}

private fun getEncryptedSecret(pairedSecurityKey:PairedSecurityKey):ByteArray {
    val encryptedSessionStorage =
            AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext())
    return encryptedSessionStorage.getEncryptedSessionSecret(pairedSecurityKey.getSecurityKeyAid())
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Decryption
Decryption is possible when the user connects the correct Security Key to the device.
Similar to the Pairing step, this can be done with the ``SecurityKeyCallback`` when the Security Key is discovered.
For this, the ``PairedSecurityKey`` object is retrieved using the AID of the connected Security Key and the ``encryptedSecret`` is decrypted.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public class DecryptActivity extends AppCompatActivity implements SecurityKeyCallback<OpenPgpSecurityKey> {
    private PinProvider pinProvider;
    private PairedSecurityKeyStorage pairedSecurityKeyStorage;
    private EncryptedSessionStorage encryptedSessionStorage;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SecurityKeyManager.getInstance().registerCallback(
                OpenPgpSecurityKeyConnectionMode.getInstance(), this, this);
        pinProvider =
                AndroidPreferenceSimplePinProvider.getInstance(getApplicationContext());
        pairedSecurityKeyStorage =
                AndroidPreferencePairedSecurityKeyStorage.getInstance(getApplicationContext());
        encryptedSessionStorage =
                AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext());
    }

    @Override
    public void onSecurityKeyDiscovered(@NonNull OpenPgpSecurityKey securityKey) {
        byte[] encryptedSecret = encryptedSessionStorage.getEncryptedSessionSecret(
                securityKey.getOpenPgpInstanceAid());
        decrypt(securityKey, encryptedSecret);
    }

    public void decrypt(OpenPgpSecurityKey securityKey, byte[] encryptedSecret) {
        PairedSecurityKey pairedSecurityKey = pairedSecurityKeyStorage.getPairedSecurityKey(
                securityKey.getOpenPgpInstanceAid());

        OpenPgpPairedDecryptor decryptor =
                new OpenPgpPairedDecryptor(securityKey, pinProvider, pairedSecurityKey);
        ByteSecret secret = decryptor.decryptSessionSecret(encryptedSecret);
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Prevent Re-Creation of Activity with USB Security Keys

Besides the functionalities used by our SDK, some Security Keys register themselves as USB keyboards to be able to insert One Time Passwords (OTP) when touching the golden disc.
Thus, when inserting a Security Key into the USB port, Android recognizes a new keyboard and re-creates the current activity.

To prevent this, add ``keyboard|keyboardHidden`` to the activity's ``configChanges`` in your ``AndroidManifest.xml``:

```xml
<activity
    android:name=".MyCustomActivity"
    android:configChanges="keyboard|keyboardHidden"
... >
```


## Congratulations!

That's all! If you have any questions, don't hesitate to contact us: <ul class="connect-links fa-ul"><li><i class="fa-li fas fa-comments"></i><a href="mailto:support@hwsecurity.dev?subject=Developer Question&amp;body=I have a question regarding...">Ask us by email</a></li></ul>
