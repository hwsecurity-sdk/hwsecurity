package de.cotech.hw.internal;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;
import de.cotech.hw.SecurityKeyManagerConfig;
import io.sentry.core.Sentry;


@RestrictTo(Scope.LIBRARY_GROUP)
public class HwSentry {
    private static boolean isSentryAvailable = false;
    private static boolean isCaptureExceptionOnInternalError = false;

    public static void initializeIfAvailable(SecurityKeyManagerConfig config) {
        if (config.isSentrySupportDisabled()) {
            return;
        }
        try {
            Class.forName("io.sentry.core.Sentry");
            isSentryAvailable = true;
            isCaptureExceptionOnInternalError = config.isSentryCaptureExceptionOnInternalError();
        } catch (ClassNotFoundException e) {
            isSentryAvailable = false;
        }
    }

    public static void addBreadcrumb(String format, Object... args) {
        if (!isSentryAvailable) {
            return;
        }
        String message = String.format(format, args);
        Sentry.addBreadcrumb("hwsecurity: " + message);
    }

    public static void captureException(Exception exception) {
        if (!isSentryAvailable || !isCaptureExceptionOnInternalError) {
            return;
        }
        Sentry.captureException(exception);
    }

    public static void addTag(String tag, String value) {
        if (!isSentryAvailable) {
            return;
        }
        Sentry.setTag(tag, value);
    }

    public static void removeTag(String tag) {
        if (!isSentryAvailable) {
            return;
        }
        Sentry.removeTag(tag);
    }
}
