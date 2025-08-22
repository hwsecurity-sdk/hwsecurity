+++
title = "PIV for TLS Client Certificates"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 5

# Add menu entry to sidebar.
linktitle = "PIV for TLS Client Certificates"
[menu.docs]
  parent = "hw-security"
  weight = 5
+++

In this guide, you'll learn how to use PIV cards and security keys for TLS client certificate authentication.

<div class="row">
  <div class="col-sm-12 text-center">
  Fork sample code on Github:
  <a href="https://github.com/cotechde/hwsecurity-samples/tree/main/tls-sample"><img class="mx-auto d-block" src="/img/github-badge-small.png" alt="Get Sample on Github" height="63" style="margin:0;"></a>
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
    // PIV cards
    implementation 'de.cotech:hwsecurity-piv:{{< hwsecurity-current-version >}}'
    
    // OkHttp for HTTP requests
    implementation 'com.squareup.okhttp3:okhttp:3.14.2'
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


## Show Security Key Dialog and Receive Callbacks

In this guide, we use the ``PivSecurityKeyDialogFragment`` to show a neat kepad for PIN input.
It also handles security key errors, for example when a wrong PIN is entered.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
private void showSecurityKeyDialog() {
    SecurityKeyDialogOptions options = SecurityKeyDialogOptions.builder()
            //.setPinLength(4) // security keys with a fixed PIN and PUK length improve the UX
            //.setPukLength(8)
            .setPreventScreenshots(!BuildConfig.DEBUG)
            .build();

    SecurityKeyDialogFragment<PivSecurityKey> securityKeyDialogFragment =
            PivSecurityKeyDialogFragment.newInstance(options);
    securityKeyDialogFragment.show(getSupportFragmentManager());
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

Implement ``SecurityKeyDialogCallback<PivSecurityKey>`` in your Activity and override ``onSecurityKeyDialogDiscovered`` to receive callbacks from the ``securityKeyDialogFragment`` when a security key is discovered over NFC (or Security Keys over USB).

Using your favorite HTTP client, such as OkHttp, you can create a request using the ``SSLContext`` created by ``SecurityKeyTlsClientCertificateAuthenticator``.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
@Override
public void onSecurityKeyDialogDiscovered(@NonNull SecurityKeyDialogInterface dialogInterface,
                                          @NonNull PivSecurityKey securityKey,
                                          @Nullable PinProvider pinProvider) throws IOException {
    try {
        SecurityKeyTlsClientCertificateAuthenticator clientCertificateAuthenticator =
                securityKey.createSecurityKeyClientCertificateAuthenticator(pinProvider);
        SSLContext sslContext = clientCertificateAuthenticator.buildInitializedSslContext();

        OkHttpClient httpClient = new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory())
                .build();
        Request request = new Request.Builder()
                .url("https://tls.hwsecurity.dev")
                .build();
        Response response = httpClient.newCall(request).execute();

        showDebugInfo(response);
        dialogInterface.dismiss();
    } catch (CertificateException e) {
        Log.e(MyCustomApplication.TAG, "CertificateException", e);
    } catch (NoSuchAlgorithmException e) {
        Log.e(MyCustomApplication.TAG, "NoSuchAlgorithmException", e);
    } catch (KeyManagementException e) {
        Log.e(MyCustomApplication.TAG, "KeyManagementException", e);
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
