# Encrypting Secrets

In this Encryption Guide, you learn how to integrate the SDK in your app, pair with a Security Key, and use it for data encryption.


## Add the SDK to Your Project

Add this to your ``build.gradle``:

```gradle

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


## Using Secrets instead of Passwords

> [!CAUTION]
> Security Keys themselves are not directly used to encrypt full files or databases.
>
> Instead, they decrypt short secrets, that are in turn used to encrypt data.

When you would normally use a user-chosen password/passphrase to encrypt data, you now generate a random secret with the SDK's ``SecretGenerator``.
This secret is used for in-app data encryption, while the secret itself is encrypted to the Security Key.
Thus, the physical Security Key replaces user-chosen passwords.


```java
public ByteSecret generateSecret() {
    SecretGenerator secretGenerator = SecretGenerator.getInstance();
    ByteSecret secret = secretGenerator.createRandom(32);

    // use returned secret for data encryption in-app
    return secret;
}
```

## Encrypt to Security Keys
When the Security Key is paired and available as a ``PairedSecurityKey``, the generated secret can be encrypted.
Encrypting secrets "to a Security Key" can be done anywhere in your app.
Usually, it is done once during setup.
For encryption, it is **NOT** required that Security Key is connected to the device.

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

## Storing and Retrieving Encrypted Secrets
The SDK offers utilities for persisting the ``encryptedSecret``.
In this basic guide, we store it in an Android preference XML file using the Security Key's Application Identifier (AID) for later retrieval.


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

## Decryption
Decryption is possible when the user connects the correct Security Key to the device.
Similar to the Pairing step, this can be done with the ``SecurityKeyCallback`` when the Security Key is discovered.
For this, the ``PairedSecurityKey`` object is retrieved using the AID of the connected Security Key and the ``encryptedSecret`` is decrypted.


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

That's all!
