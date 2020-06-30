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


import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import android.annotation.SuppressLint;
import androidx.annotation.NonNull;

import com.google.auto.value.AutoValue;

import de.cotech.hw.internal.transport.Version;
import de.cotech.hw.util.Hex;

@AutoValue
public abstract class OpenPgpAid {

	public abstract byte[] getAid();

	public abstract Version getOpenPgpSpecVersion();

	public abstract int getManufacturer();

	public abstract byte[] getSerialNumber();

	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg-verein.git;a=blob_plain;f=office/misc/OpenPGP-Card-Vendors
	private static final Map<Integer, String> OPENPGP_HARDWARE = createVendorMap();

	private static Map<Integer, String> createVendorMap() {
		@SuppressLint("UseSparseArrays") Map<Integer, String> result = new HashMap<>();
		result.put(0x0000, "Testcard");
		result.put(0x0001, "PPC Card Systems");
		result.put(0x0002, "Prism Payment"); // Prism Payment Technologies
		result.put(0x0003, "OpenFortress"); // OpenFortress Digital signatures
		result.put(0x0004, "Wewid"); // Wewid AB
		result.put(0x0005, "ZeitControl"); // ZeitControl cardsystems GmbH
		result.put(0x0006, "YubiKey"); // Yubico AB
		result.put(0x0007, "OpenKMS");
		result.put(0x0008, "LogoEmail");
		result.put(0x0009, "Fidesmo"); // Fidesmo AB
		result.put(0x000A, "Dangerous Things");
		result.put(0x002A, "Magrathea");
		result.put(0x0042, "GnuPG e.V.");
		result.put(0x1337, "Warsaw Hackerspace");
		result.put(0x2342, "warpzone e.V.");
		result.put(0x4354, "Cotech Card"); // Confidential Technologies
		result.put(0x63AF, "Trustica"); // Trustica s.r.o
		result.put(0xBD0E, "Paranoidlabs");
		result.put(0xF517, "FSFJ"); // Free Software Initiative of Japan
		result.put(0xFFFF, "Testcard");
		//** 0xFF00..FFFE - Range reserved for randomly assigned serial numbers.
		//
		// Serialnumbers with manufacturer ID in this range are an exception
		// to the rule that they should be unique.  It is expected that such a
		// serialnumber is assigned using a true random function which
		// generates 5 bytes (4 for the actual serial number and one to select
		// a manufacturer ID out of this range). Note, that the 0xffff is not
		// part of this range.  Implementers using serial numbers as a unique
		// ID should keep in mind that duplicates may happen.  Using the of
		// manufacturer IDs out of this range should only be done if no other
		// way of obtaining a manufacturer ID is possible.
		return Collections.unmodifiableMap(result);
	}

	public static OpenPgpAid create(@NonNull byte[] aid) {
		ByteBuffer aidBuffer = ByteBuffer.wrap(aid);

		// skip registered ID and app id (D2 76 00 01 24 | 01)
		aidBuffer.position(6);

		byte[] buf;

		buf = new byte[2];
		aidBuffer.get(buf);
		Version openPgpSpecVersion = Version.create(buf[0] + "." + buf[1]);

		int manufacturer = aidBuffer.getShort();

		buf = new byte[4];
		aidBuffer.get(buf);
		byte[] serialNumber = buf;

		return new AutoValue_OpenPgpAid(aid, openPgpSpecVersion, manufacturer, serialNumber);
	}

	/**
	 * GnuPG will sometimes asks you to insert "Card xxxxxxxx" where xxxxxxxx is the
	 * hexadecimal representation of the serial number.
	 * <p>
	 * So we do not convert the serial number to decimals. Instead we directly print the
	 * hexadecimal representation.
	 * <p>
	 * This is also why Yubikey NEOs store the serial number in BCD code so if your
	 * YubiKey NEO has serial number 4711 you would use xxxxxxxx=00004711.
	 */
	public String getSerialNumberString() {
		return Hex.encodeHexString(getSerialNumber());
	}

	public String getSecurityKeyName() {
		return OPENPGP_HARDWARE.get(getManufacturer());
	}

	@Override
	public String toString() {
		return Hex.encodeHexString(getAid());
	}
}
