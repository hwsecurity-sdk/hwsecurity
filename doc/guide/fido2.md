# FIDO2 / WebAuthn

FIDO2 support has been implemented in our Hardware Security SDK starting with version 4.0.0.

Fork sample code on Github: https://github.com/cotechde/hwsecurity-samples/tree/main/fido-sample

## Add the SDK to Your Project

Add this to your ``build.gradle``:

```gradle

dependencies {
    // FIDO2/WebAuthn implementation
    implementation 'de.cotech:hwsecurity-fido2:{{< hwsecurity-current-version >}}'
}
```


## Initialize the Hardware Security SDK

To use the SDK's functionality in your app, you need to initialize the ``SecurityKeyManager`` first.
This is the central class of the SDK, which dispatches incoming NFC and USB connections.
Perform this initialization in the ``onCreate`` method of your ``Application`` subclass.
This ensures Security Keys are reliably dispatched by your app while in the foreground.

We start by creating a new class which extends ``android.app.Application`` as follows:

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


Then, register your ``MyCustomApplication`` in your ``AndroidManifest.xml``:

```xml
<application 
    android:name=".MyCustomApplication"
    android:label="@string/app_name" 
... >
```

## FIDO2 Registration

Show our ``WebAuthnDialogFragment`` to register a Security Key:

```kotlin
private fun showRegisterDialog() {
    val username = "testuser"
    val origin = "https://fido-login.example.com"

    // Make a registration request to the server. In a real application, this would perform
    // an HTTP request. The server sends us a challenge (and some other data), that we proceed
    // to sign with our FIDO2 Security Key.
    // The request usually uses the username.
    val registerRequest = ... // use PublicKeyCredentialCreationOptions.create() based on the server data

    // This opens a UI fragment, which takes care of the user interaction as well as all FIDO2
    // internal operations, and triggers a callback to #onMakeCredentialCallback(PublicKeyCredential).
    WebauthnDialogFragment.newInstance(PublicKeyCredentialCreate.create(origin, registerRequest))

    dialogFragment.setOnMakeCredentialCallback(onMakeCredentialCallback)
    dialogFragment.show(requireFragmentManager())
}
```

Implement ``OnMakeCredentialCallback`` and override ``onMakeCredentialResponse`` to receive callbacks from the ``WebauthnDialogFragment``:

```kotlin
private val onMakeCredentialCallback = OnMakeCredentialCallback { publicKeyCredential ->
    // Finish the FIDO2 registration with your server here
}
```

## FIDO2 Authentication

Authentication is now done by creating a ``FidoAuthenticateRequest``:

```kotlin
private fun showAuthenticateDialog() {
    val username = "testuser"
    val origin = "https://fido-login.example.com"

    // Make an authentication request to the server. In a real application, this would perform
    // an HTTP request. The server will send us a challenge based on the FIDO2 key we registered
    // before (see above), asking us to prove we still have the same key.
    // The request usually uses the username.
    val authenticateRequest = ... // use PublicKeyCredentialRequestOptions.create based on the server data

    // This opens a UI fragment, which takes care of the user interaction as well as all FIDO internal
    // operations, and triggers a callback to #OnGetAssertionCallback(PublicKeyCredential).
    WebauthnDialogFragment.newInstance(PublicKeyCredentialGet.create(origin, authenticateRequest))

    dialogFragment.setOnGetAssertionCallback(onGetAssertionCallback)
    dialogFragment.show(requireFragmentManager())
}
```
Implement ``OnGetAssertionCallback`` in your Activity and override ``onGetAssertionResponse``:

```kotlin
private val onGetAssertionCallback = OnGetAssertionCallback { publicKeyCredential ->
    // Finish the FIDO2 authentication with your server here
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
