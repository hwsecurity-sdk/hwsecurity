/*
 * Copyright (C) 2018-2020 Confidential Technologies GmbH
 *
 * You can purchase a commercial license at https://hwsecurity.dev.
 * Buying such a license is mandatory as soon as you develop commercial
 * activities involving this program without disclosing the source code
 * of your own applications.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.cotech.hw.fido;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;
import android.os.Binder;
import android.util.Base64;


public class FidoFacetIdUtil {
    @SuppressWarnings("unused") // public API
    public static String getFacetIdForApp(Context context) {
        PackageManager packageManager = context.getPackageManager();
        String[] callingPackages = packageManager.getPackagesForUid(Binder.getCallingUid());
        return getFacetIdForApp(packageManager, callingPackages[0]);
    }

    @SuppressWarnings("unused") // public API
    public static String getFacetIdForApp(Context context, String applicationId) {
        PackageManager packageManager = context.getPackageManager();
        return getFacetIdForApp(packageManager, applicationId);
    }

    private static String getFacetIdForApp(PackageManager packageManager, String applicationId) {
        try {
            PackageInfo info = getPackageInfo(packageManager, applicationId);

            byte[] encodedCertificate = getEncodedCertificate(info.signatures[0]);
            byte[] encodedCertSha1 = sha1(encodedCertificate);
            String encodedCertSha1B64 = Base64.encodeToString(encodedCertSha1,
                    Base64.DEFAULT | Base64.NO_WRAP | Base64.NO_PADDING);

            return "android:apk-key-hash:" + encodedCertSha1B64;
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to encode application signature!", e);
        } catch (NameNotFoundException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha1(byte[] encodedCertificate) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        return md.digest(encodedCertificate);
    }

    private static byte[] getEncodedCertificate(Signature signature) throws CertificateException {
        InputStream x509CertificateByteStream = new ByteArrayInputStream(signature.toByteArray());
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate c = (X509Certificate) cf.generateCertificate(x509CertificateByteStream);
        return c.getEncoded();
    }

    @SuppressLint("PackageManagerGetSignatures")
    private static PackageInfo getPackageInfo(PackageManager packageManager, String applicationId)
            throws NameNotFoundException {
        return packageManager.getPackageInfo(applicationId, PackageManager.GET_SIGNATURES);
    }
}
