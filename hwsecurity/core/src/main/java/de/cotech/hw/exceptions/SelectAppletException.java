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

package de.cotech.hw.exceptions;


import java.util.List;

import de.cotech.hw.SecurityKeyException;


public class SelectAppletException extends SecurityKeyException {
    private static final long serialVersionUID = 5279541795131441233L;

    private List<byte[]> aidPrefixes;

    private String protocol;

    public SelectAppletException(List<byte[]> aidPrefixes, String protocol) {
        super("Security Key does not support " + protocol + ".", "SELECT_APPLET_FAILED", 0x00);
        this.aidPrefixes = aidPrefixes;
        this.protocol = protocol;
    }

    public List<byte[]> getAllowedAidPrefixes() {
        return aidPrefixes;
    }

    public String getProtocol() {
        return protocol;
    }
}
