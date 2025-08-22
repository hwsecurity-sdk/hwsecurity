+++
title = "SSH Authentication with SSHJ"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 4

aliases = ["ssh"]

# Add menu entry to sidebar.
linktitle = "SSH Authentication with SSHJ"
[menu.docs]
  parent = "hw-security"
  weight = 4
+++

In this guide, you'll learn how to integrate the Hardware Security SDK in your app to implement SSH authentication with security keys and smartcards.
The Hardware Security SDK will automatically…

  1. retrieve the publickey from the security key and use it for the SSH connection.  
  2. cryptographically sign the SSH challenge using the security key.

<div class="row">
  <div class="col-sm-6 text-center">
  Fork sample code on Github:
  <a href="https://github.com/cotechde/hwsecurity-samples/tree/main/pgp-piv-ssh-sample"><img class="mx-auto d-block" src="/img/github-badge-small.png" alt="Get Sample on Github" height="63" style="margin:0;"></a>
  </div>
  
  <div class="col-sm-6 text-center">
  Try on Google Play:
  <a href="https://play.google.com/store/apps/details?id=de.cotech.hw.ssh.sample"><img class="mx-auto d-block" src="/img/google-play-badge-small.png" alt="Get it on Google Play" height="63" style="margin:0;"></a>
  </div>
</div>


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
    // For use with OpenPGP Cards
    implementation 'de.cotech:hwsecurity-openpgp:{{< hwsecurity-current-version >}}'
    // Or with PIV cards
    //implementation 'de.cotech:hwsecurity-piv:{{< hwsecurity-current-version >}}'

    // SSHJ bridge
    implementation 'de.cotech:hwsecurity-sshj:{{< hwsecurity-current-version >}}'
    
    // SSHJ library
    implementation 'com.hierynomus:sshj:0.31.0'
    implementation 'org.bouncycastle:bcprov-jdk15on:1.65' // Bouncy Castle for modern publickey support
}
```

## Initialize the Hardware Security SDK

To use the SDK's functionality in your app, you need to initialize the ``SecurityKeyManager`` first.
This is the central class of the SDK, which dispatches incoming NFC and USB connections.
Perform this initialization in the ``onCreate`` method of your ``Application`` subclass.
This ensures Security Keys are reliably dispatched by your app while in the foreground.

We start by creating a new class which extends ``android.app.Application`` as follows:

{{% code-tabs %}}
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
{{% /code-tabs %}}

Then, register your ``MyCustomApplication`` in your ``AndroidManifest.xml``:

```xml
<application 
    android:name=".MyCustomApplication"
    android:label="@string/app_name" 
...>
```

## Show Security Key Dialog and Receive Callbacks

In this guide, we use the ``OpenPgpSecurityKeyDialogFragment`` to show a neat kepad for PIN input.
It also handles security key errors, for example when a wrong PIN is entered.

{{% code-tabs %}}
{{% code-tab "Kotlin" %}}
```kotlin
private fun showSecurityKeyDialog() {
    val options = SecurityKeyDialogOptions.builder()
        //.setPinLength(4) // security keys with a fixed PIN and PUK length improve the UX
        //.setPukLength(8)
        .setShowReset(true) // show button to reset/unblock of PIN using the PUK
        .build()

    val securityKeyDialogFragment = OpenPgpSecurityKeyDialogFragment.newInstance(options)
    // if you like to use PIV:
    //val securityKeyDialogFragment = PivSecurityKeyDialogFragment.newInstance(options)

    securityKeyDialogFragment.show(supportFragmentManager)
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

Implement ``SecurityKeyDialogCallback<OpenPgpSecurityKey>`` (or, if you are using PIV cards: ``SecurityKeyDialogCallback<PivSecurityKey>``) in your Activity and override ``onSecurityKeyDialogDiscovered`` to receive callbacks from the ``securityKeyDialogFragment`` when a security key is discovered over NFC (or Security Keys over USB):

{{% code-tabs %}}
{{% code-tab "Kotlin" %}}
```kotlin
@UiThread
override fun onSecurityKeyDialogDiscovered(
    dialogInterface: SecurityKeyDialogInterface,
    securityKey: OpenPgpSecurityKey,
    pinProvider: PinProvider?
) {
    val loginName = "cotech"
    val loginHost = "ssh.hwsecurity.dev"

    connectToSsh(loginName, loginHost, dialogInterface, securityKey, pinProvider!!)
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Threading and Exception Handling

The actual SSH connection is deferred to a new thread so that network operations are not blocking the main thread.
To properly handle Exceptions, ``deferred.await()`` is used.
``IOExceptions`` are posted to the ``securityKeyDialogFragment`` using the ``SecurityKeyDialogInterface.postError()`` for user feedback.
To bridge SSHJ authentication to the Security Key, the ``SecurityKeySshjAuthMethod`` class from the "de.cotech:hwsecurity-sshj" artifact is used.

{{% code-tabs %}}
{{% code-tab "Kotlin" %}}
```kotlin
private fun connectToSsh(
        dialogInterface: SecurityKeyDialogInterface,
        securityKeyAuthenticator: SecurityKeyAuthenticator
) = GlobalScope.launch(Dispatchers.Main) {
    val loginName = textDataUser.text.toString()
    val loginHost = textDataHost.text.toString()
    textLog.text = ""

    dialogInterface.postProgressMessage("Retrieving public key from Security Key…")
    val deferred = GlobalScope.async(Dispatchers.IO) {
        val securityKeySshjAuthMethod = SecurityKeySshjAuthMethod(securityKeyAuthenticator)
        sshjConnection(dialogInterface, loginHost, loginName, securityKeySshjAuthMethod)
    }

    try {
        deferred.await()
    } catch (e: IOException) {
        dialogInterface.postError(e)
    } catch (e: Exception) {
        Log.e(MyCustomApplication.TAG, "Exception", e)
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## SSHJ Connection

The actual SSH connection can be done according to the SSHJ documentation.
After successfull authentication, ``securityKeyDialogFragment`` must be dismissed manually.

{{% code-tabs %}}
{{% code-tab "Kotlin" %}}
```kotlin
@WorkerThread
private fun sshjConnection(
        dialogInterface: SecurityKeyDialogInterface,
        loginHost: String,
        loginName: String,
        securityKeySshjAuthMethod: SecurityKeySshjAuthMethod
) {
    dialogInterface.postProgressMessage("Connecting to SSH server…")

    val sshClient = SSHClient()
    sshClient.timeout = TIMEOUT_MS_CONNECT
    sshClient.connect(loginHost)
    val session: Session?

    sshClient.auth(loginName, securityKeySshjAuthMethod)
    session = sshClient.startSession()

    session.allocateDefaultPTY()
    val shell = session.startShell()

    val baos = ByteArrayOutputStream()
    baos.write("Server Output: ".toByteArray(), 0, 15)

    StreamCopier(shell.inputStream, baos, LoggerFactory.DEFAULT)
            .bufSize(shell.localMaxPacketSize)
            .spawn("stdout")

    StreamCopier(shell.errorStream, baos, LoggerFactory.DEFAULT)
            .bufSize(shell.localMaxPacketSize)
            .spawn("stderr")

    val startTime = SystemClock.elapsedRealtime()
    while (sshClient.isConnected) {
        if (SystemClock.elapsedRealtime() - startTime > MAX_CONNECTION_TIME) {
            Log.d("SSH", "SSH client automatically disconnected after $MAX_CONNECTION_TIME ms.")
            session?.close()
            sshClient.disconnect()
            break
        }
    }

    // close dialog after successful authentication
    dialogInterface.successAndDismiss()
    Log.d("SSH", "SSH connection successful!")
    Log.d("SSH", baos.toString())
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

## ssh.hwsecurity.dev Test Server

To test your implementation, we provide a SSH test server at ``ssh.hwsecurity.dev``.
When logging in with the username ``cotech``, it simply returns the used SSH algorithm and public key.
If an OpenSSH certificate is used, it is returned instead.

### Public Key

Try it with your OpenSSH client first:

```shell
user@laptop:~$ ssh cotech@ssh.hwsecurity.dev

Hardware Security SDK - SSH Sample

You are using a publickey (not certificate) with type:
ssh-rsa

Your full key is:
AAAAB3NzaC1yc2EAAAADAQABAAABAQC2mh1oganCTRdymQn864LQHkibEyyeC26I5FF4NLv03QU0OxR
iIS3iLpZXJA+hL4ARBDxMWeYnytcgj2n9PLiOLJijgTyfEqVBAp7HpqnXxcKLj+cl4LpBhs81nfdeN1
osNkpsdb7J2ZprSIh8eweIw1ZLB1s6J3FQcxhOfo1I0VYV4u512ra6+13w6CvFqqbAyx9VgvNfNB9LV
rgHP0QWFs7qhtj+wWIS835R5sOiwwC2ELN2nEZKsOlQrp/Um4uFoD/UUqiqznZVNW3l8yKEWTE4jVUg
txg0iFoBqDBKk5N/2z4jUz4MaKZ0LPhlp3hL/E0sDifMwtLxziawaRJn


Bye!

Connection to ssh.hwsecurity.dev closed.
```

## Congratulations!

That's all! If you have any questions, don't hesitate to contact us: <ul class="connect-links fa-ul"><li><i class="fa-li fas fa-comments"></i><a href="mailto:support@hwsecurity.dev?subject=Developer Question&amp;body=I have a question regarding...">Ask us by email</a></li></ul>
