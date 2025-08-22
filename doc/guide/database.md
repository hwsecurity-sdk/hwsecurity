+++
title = "Encrypted Database"

draft = false  # Is this a draft? true/false
toc = true  # Show table of contents? true/false
type = "guide"  # Do not modify.
weight = 7

# Add menu entry to sidebar.
linktitle = "Encrypted Database with Room"
[menu.docs]
  parent = "hw-security"
  weight = 7
+++




In this guide, you'll learn how to implement an encrypted Android database that is only decrypted with a specific Security Key.
It uses our Hardware Security SDK and the [Room Persistence Library](https://developer.android.com/topic/libraries/architecture/room).
Internally, [SQLCipher](https://www.zetetic.net/sqlcipher/) and [CWAC-SafeRoom](https://github.com/commonsguy/cwac-saferoom) are used.

The main workflows are:

* The user pairs a Security Key with the app during the on-boarding process
    1. A cryptographic key is generated on the Security Key
    2. A random 32 byte secret is generated
    3. The secret is used to encrypt the database
    4. The secret is encrypted to the cryptographic key (Public-Key Cryptography) on the Security Key
    5. The encrypted secret is stored inside the app
* The user "unlocks" the app when it is opened
    1. The encrypted secret is retrieved from the app
    2. The Security Key is used to decrypt the encrypted secret (Public-Key Cryptography)
    3. The secret is used to decrypt the database in-memory


<div class="row">
  <div class="col-sm-12 text-center">
  Fork sample code on Github:
  <a href="https://github.com/cotechde/hwsecurity-samples/tree/main/database-sample"><img class="mx-auto d-block" src="/img/github-badge-small.png" alt="Get Sample on Github" height="63" style="margin:0;"></a>
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
    // CWAC-SafeRoom Maven repository
    maven { url "https://s3.amazonaws.com/repo.commonsware.com" }
}

dependencies {
    // OpenPGP Card Specification
    implementation 'de.cotech:hwsecurity-openpgp:{{< hwsecurity-current-version >}}'
    
    // Room Persistence Library
    implementation "androidx.room:room-runtime:2.1.0"
    annotationProcessor "androidx.room:room-compiler:2.1.0"

    // SQLCipher and CWAC-SafeRoom
    implementation "com.commonsware.cwac:saferoom.x:1.1.2"
    implementation "net.zetetic:android-database-sqlcipher:4.2.0@aar"
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

## Room

Following the [basic Training Guide for Room](https://developer.android.com/training/data-storage/room), we create one simple entity and one DAO:

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
@Entity
public class User {
    @PrimaryKey
    public int uid;

    @ColumnInfo(name = "first_name")
    public String firstName;

    @ColumnInfo(name = "last_name")
    public String lastName;

    @NonNull
    @Override
    public String toString() {
        return "uid=" + uid + "\nfirst_name=" + firstName + "\nlast_name=" + lastName;
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
@Dao
public interface UserDao {
    @Query("SELECT * FROM user")
    List<User> getAll();

    @Query("SELECT * FROM user WHERE uid IN (:userIds)")
    List<User> loadAllByIds(int[] userIds);

    @Query("SELECT * FROM user WHERE first_name LIKE :first AND " +
            "last_name LIKE :last LIMIT 1")
    User findByName(String first, String last);

    @Insert
    void insertAll(User... users);

    @Delete
    void delete(User user);
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## Database Instance

The ``RoomDatabase`` allows decryption with a ``ByteSecret``.
It is implemented as a Singelton to ensure that only one database is decrypted and held in-memory.

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
@Database(entities = {User.class}, version = 1)
public abstract class EncryptedDatabase extends RoomDatabase {

    private static EncryptedDatabase sInstance;

    @VisibleForTesting
    public static final String DATABASE_NAME = "encrypted-sample-db";

    public static EncryptedDatabase decryptAndGetInstance(final Context context, ByteSecret secret) {
        if (sInstance == null) {
            synchronized (EncryptedDatabase.class) {
                if (sInstance == null) {
                    sInstance = buildDatabase(context.getApplicationContext(), secret);
                }
            }
        }
        return sInstance;
    }

    public static EncryptedDatabase getInstance() {
        if (sInstance == null) {
            return null;
        } else {
            return sInstance;
        }
    }

    private static EncryptedDatabase buildDatabase(final Context appContext, ByteSecret secret) {
        SafeHelperFactory factory = new SafeHelperFactory(secret.getByteCopyAndClear());

        return Room.databaseBuilder(appContext, EncryptedDatabase.class, DATABASE_NAME)
                .openHelperFactory(factory)
                .addCallback(new Callback() {
                    @Override
                    public void onCreate(@NonNull SupportSQLiteDatabase db) {
                        super.onCreate(db);
                        // TODO: populate database with initial data
                    }
                })
                .build();
    }

    public abstract UserDao userDao();

}
```
{{% /code-tab %}}
{{% /code-tabs %}}


## Base Activity

The ``BaseActivity`` ensures that the user first pairs a Security Key with the app and decrypts the database before usage.
All normal Activities in your app should extend this ``BaseActivity`` for this (see [``MainActivity``](#database-operations-with-room)).

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
class BaseActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        AndroidPreferencesEncryptedSessionStorage masterSecretPrefs = AndroidPreferencesEncryptedSessionStorage.getInstance(this);
        boolean hasNoSecret = !masterSecretPrefs.hasAnyEncryptedSessionSecret();
        if (hasNoSecret) {
            startSetup();
            return;
        }

        if (EncryptedDatabase.getInstance() == null) {
            decryptDatabase();
            return;
        }
    }

    void startSetup() {
        Intent intent = new Intent(this, SetupActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
        startActivity(intent);
        finish();
    }

    void decryptDatabase() {
        Intent intent = new Intent(this, DecryptActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
        startActivity(intent);
        finish();
    }
}

```
{{% /code-tab %}}
{{% /code-tabs %}}


## SetupActivity

The ``SetupActivity`` is started when no Security Key has been paired with the app, i.e. the database has not been initialized before.
It executes the following steps:

1. A cryptographic key is generated on the Security Key
2. A random 32 byte secret is generated
3. The secret is used to encrypt the database
4. The secret is encrypted to the cryptographic key (Public-Key Cryptography) on the Security Key
5. The encrypted secret is stored inside the app

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public class SetupActivity extends AppCompatActivity implements SecurityKeyCallback<OpenPgpSecurityKey> {
    private PinProvider pinProvider;
    private PairedSecurityKeyStorage pairedSecurityKeyStorage;

    private boolean showWipeDialog = true;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup);

        SecurityKeyManager.getInstance().registerCallback(
                OpenPgpSecurityKeyConnectionMode.getInstance(), this, this);

        pinProvider =
                AndroidPreferenceSimplePinProvider.getInstance(getApplicationContext());
        pairedSecurityKeyStorage =
                AndroidPreferencePairedSecurityKeyStorage.getInstance(getApplicationContext());
    }

    @Override
    public void onSecurityKeyDiscovered(@NonNull OpenPgpSecurityKey securityKey) {
        if (showWipeDialog && !securityKey.isSecurityKeyEmpty()) {
            DialogInterface.OnClickListener dialogClickListener = (dialog, which) -> {
                switch (which) {
                    case DialogInterface.BUTTON_POSITIVE:
                        showWipeDialog = false;
                        break;

                    case DialogInterface.BUTTON_NEGATIVE:
                        break;
                }
            };

            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setMessage("The Security Key is NOT empty! Wipe and generate a new key?")
                    .setPositiveButton("Yes", dialogClickListener)
                    .setNegativeButton("No", dialogClickListener)
                    .show();
        } else {
            setupDatabase(securityKey);
        }
    }

    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
    }

    @Override
    public void onSecurityKeyDisconnected(@NonNull OpenPgpSecurityKey securityKey) {
    }

    private void setupDatabase(OpenPgpSecurityKey securityKey) {
        // TODO: use something better than AsyncTask in your real app!
        @SuppressLint("StaticFieldLeak")
        AsyncTask task = new AsyncTask<Object, Object, String>() {

            @Override
            protected String doInBackground(Object[] objects) {
                PairedSecurityKey pairedSecurityKey = pairAndStoreSecurityKey(securityKey);
                if (pairedSecurityKey == null) {
                    return "failed to generate keys and pair Security Key!";
                }

                ByteSecret secret = generateSecret();
                byte[] encryptedSecret = encryptToSecurityKey(pairedSecurityKey, secret);

                saveEncryptedSecret(pairedSecurityKey, encryptedSecret);

                EncryptedDatabase.decryptAndGetInstance(getApplicationContext(), secret);
                return "successfully paired key, encrypted database with random secret that is encrypted to the security key";
            }

            @Override
            protected void onPostExecute(String returnString) {
                super.onPostExecute(returnString);
                Toast.makeText(SetupActivity.this, returnString, Toast.LENGTH_LONG).show();

                Intent intent = new Intent(SetupActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
            }
        };
        task.execute();
    }

    private PairedSecurityKey pairAndStoreSecurityKey(OpenPgpSecurityKey securityKey) {
        try {
            // OpenPgpSecurityKey operations are blocking, consider executing them in a new thread
            PairedSecurityKey pairedSecurityKey = securityKey.setupPairedKey(pinProvider);
            // Store the pairedSecurityKey. That way we can use it for encryption at any point
            pairedSecurityKeyStorage.addPairedSecurityKey(pairedSecurityKey);

            return pairedSecurityKey;
        } catch (IOException e) {
            return null;
        }
    }

    public ByteSecret generateSecret() {
        SecretGenerator secretGenerator = SecretGenerator.getInstance();
        return secretGenerator.createRandom(32);
    }

    public byte[] encryptToSecurityKey(PairedSecurityKey pairedSecurityKey, ByteSecret secret) {
        return new PairedEncryptor(pairedSecurityKey).encrypt(secret);
    }

    private void saveEncryptedSecret(PairedSecurityKey pairedSecurityKey, byte[] encryptedSecret) {
        EncryptedSessionStorage encryptedSessionStorage =
                AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext());
        encryptedSessionStorage.setEncryptedSessionSecret(
                pairedSecurityKey.getSecurityKeyAid(), encryptedSecret);
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}

## DecryptActivity

The ``DecryptActivity`` is started when no decrypted database instance is currently held in-memory.
It executes the following steps:

1. The encrypted secret is retrieved from the app
2. The Security Key is used to decrypt the encrypted secret (Public-Key Cryptography)
3. The secret is used to decrypt the database in-memory

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public class DecryptActivity extends AppCompatActivity implements SecurityKeyCallback<OpenPgpSecurityKey> {
    private PinProvider pinProvider;
    private PairedSecurityKeyStorage pairedSecurityKeyStorage;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_unlock);

        SecurityKeyManager.getInstance().registerCallback(
                OpenPgpSecurityKeyConnectionMode.getInstance(), this, this);

        pinProvider =
                AndroidPreferenceSimplePinProvider.getInstance(getApplicationContext());
        pairedSecurityKeyStorage =
                AndroidPreferencePairedSecurityKeyStorage.getInstance(getApplicationContext());
    }

    @Override
    public void onSecurityKeyDiscovered(@NonNull OpenPgpSecurityKey securityKey) {
        decryptDatabase(securityKey);
    }

    @Override
    public void onSecurityKeyDiscoveryFailed(@NonNull IOException exception) {
    }

    @Override
    public void onSecurityKeyDisconnected(@NonNull OpenPgpSecurityKey securityKey) {
    }

    private void decryptDatabase(OpenPgpSecurityKey securityKey) {
        // TODO: use something better than AsyncTask in your real app!
        @SuppressLint("StaticFieldLeak")
        AsyncTask task = new AsyncTask<Object, Object, String>() {

            @Override
            protected String doInBackground(Object[] objects) {
                PairedSecurityKey pairedSecurityKey = getPairedSecurityKey();
                if (pairedSecurityKey == null) {
                    return "failed to get paired security key";
                }

                byte[] encryptedSecret = getEncryptedSecret(pairedSecurityKey);
                ByteSecret secret = decrypt(securityKey, encryptedSecret);
                if (secret == null) {
                    return "decrypt failed";
                }

                // decrypt database
                EncryptedDatabase.decryptAndGetInstance(getApplicationContext(), secret);
                return "successfully decrypted database!";
            }

            @Override
            protected void onPostExecute(String returnString) {
                super.onPostExecute(returnString);
                Toast.makeText(DecryptActivity.this, returnString, Toast.LENGTH_LONG).show();

                Intent intent = new Intent(DecryptActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
            }
        };
        task.execute();
    }

    private PairedSecurityKey getPairedSecurityKey() {
        // for simplicity, we assume a single paired security key
        return pairedSecurityKeyStorage.getAllPairedSecurityKeys().iterator().next();
    }

    private byte[] getEncryptedSecret(PairedSecurityKey pairedSecurityKey) {
        EncryptedSessionStorage encryptedSessionStorage =
                AndroidPreferencesEncryptedSessionStorage.getInstance(getApplicationContext());
        return encryptedSessionStorage.getEncryptedSessionSecret(pairedSecurityKey.getSecurityKeyAid());
    }

    public ByteSecret decrypt(OpenPgpSecurityKey securityKey, byte[] encryptedSecret) {
        try {
            PairedSecurityKey pairedSecurityKey = pairedSecurityKeyStorage.getPairedSecurityKey(
                    securityKey.getOpenPgpInstanceAid());
            OpenPgpPairedDecryptor decryptor =
                    new OpenPgpPairedDecryptor(securityKey, pinProvider, pairedSecurityKey);

            return decryptor.decryptSessionSecret(encryptedSecret);
        } catch (IOException e) {
            return null;
        }
    }
}
```
{{% /code-tab %}}
{{% /code-tabs %}}


## Database Operations with Room 

All your Activities should extend the ``BaseActivity`` to ensure previous Security Key setup and database decryption.
Database operations can be done as specified by the [Room Persistence Library](https://developer.android.com/training/data-storage/room).

{{% code-tabs %}}
{{% code-tab "Java" %}}
```java
public class MainActivity extends BaseActivity {

    private void insert() {
        // TODO: use your favorite way of threading in your app
        new Thread(() -> {
            User testUser = new User();
            testUser.firstName = "Martin";
            testUser.lastName = "Sonneborn";
            try {
                EncryptedDatabase.getInstance().userDao().insertAll(testUser);
            } catch (SQLiteConstraintException e) {
                MainActivity.this.runOnUiThread(() -> Toast.makeText(MainActivity.this, "user already inserted", Toast.LENGTH_LONG).show());
                return;
            }

            MainActivity.this.runOnUiThread(() -> Toast.makeText(MainActivity.this, "users successfully inserted", Toast.LENGTH_LONG).show());
        }).start();
    }

    private void query() {
        // TODO: use your favorite way of threading in your app
        new Thread(() -> {
            List<User> users = EncryptedDatabase.getInstance().userDao().getAll();

            MainActivity.this.runOnUiThread(() -> Toast.makeText(MainActivity.this, "users: " + users.toString(), Toast.LENGTH_LONG).show());
        }).start();
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

## Conclusion
This guide shows a general way of implementing an encrypted database using Security Keys over NFC and USB.
Some details are left to the developer, which are not covered here, such as:

* Better threading outside the main UI thread, for example with Kotlin's coroutines
* Pairing of multiple Security Keys
* Preferred user interface
* Error handling


## Congratulations!

That's all! If you have any questions, don't hesitate to contact us: <ul class="connect-links fa-ul"><li><i class="fa-li fas fa-comments"></i><a href="mailto:support@hwsecurity.dev?subject=Developer Question&amp;body=I have a question regarding...">Ask us by email</a></li></ul>
