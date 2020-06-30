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

package de.cotech.hw.openpgp.internal.openpgp;


import androidx.annotation.RestrictTo;
import androidx.annotation.RestrictTo.Scope;


@SuppressWarnings("unused") // tags from RFC 4880
@RestrictTo(Scope.LIBRARY_GROUP)
interface PublicKeyAlgorithmTags {
    int RSA_GENERAL = 1;       // RSA (Encrypt or Sign)
    int RSA_ENCRYPT = 2;       // RSA Encrypt-Only
    int RSA_SIGN = 3;          // RSA Sign-Only
    int ELGAMAL_ENCRYPT = 16;  // Elgamal (Encrypt-Only), see [ELGAMAL]
    int DSA = 17;              // DSA (Digital Signature Standard)
    /**
     * @deprecated use ECDH
     */
    int EC = 18;               // Reserved for Elliptic Curve
    int ECDH = 18;             // Reserved for Elliptic Curve (actual algorithm name)
    int ECDSA = 19;            // Reserved for ECDSA
    int ELGAMAL_GENERAL = 20;  // Elgamal (Encrypt or Sign)
    int DIFFIE_HELLMAN = 21;   // Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    int EDDSA = 22;            // EdDSA https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04

    int EXPERIMENTAL_1 = 100;
    int EXPERIMENTAL_2 = 101;
    int EXPERIMENTAL_3 = 102;
    int EXPERIMENTAL_4 = 103;
    int EXPERIMENTAL_5 = 104;
    int EXPERIMENTAL_6 = 105;
    int EXPERIMENTAL_7 = 106;
    int EXPERIMENTAL_8 = 107;
    int EXPERIMENTAL_9 = 108;
    int EXPERIMENTAL_10 = 109;
    int EXPERIMENTAL_11 = 110;
}
