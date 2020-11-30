package de.cotech.hw.fido2.internal.utils;


import java.net.MalformedURLException;
import java.net.URL;

import androidx.annotation.Nullable;
import de.cotech.hw.fido2.exceptions.FidoSecurityError;


public class RelyingPartyIdUtils {
    PublicSuffixDatabase publicSuffixDatabase = new PublicSuffixDatabase();

    /**
     * Returns the effective relying party id given the request origin and specified rpId.
     *
     * If a rpId is specified, performs a check whether this rpId is a suffix of the origin domain,
     * but not a registrable suffix from the public suffix list.
     *
     * @see <a href="https://www.w3.org/TR/webauthn-2/#rp-id">https://www.w3.org/TR/webauthn-2/#rp-id</a>
     * @see <a href="https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to">https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to</a>
     */
    public String determineRelyingPartyId(String origin, @Nullable String rpId)
            throws FidoSecurityError {
        URL callerOrigin;
        try {
            callerOrigin = new URL(origin);
        } catch (MalformedURLException e) {
            throw new FidoSecurityError("Malformed origin");
        }
        String effectiveDomain = callerOrigin.getHost();

        if (rpId == null) {
            return effectiveDomain;
        }

        if (!effectiveDomain.equals(rpId) && !effectiveDomain.endsWith("." + rpId)) {
            throw new FidoSecurityError(
                    "Security error: rpId is not a valid subdomain of caller origin!");
        }

        if (publicSuffixDatabase.getEffectiveTldPlusOne(rpId) == null) {
            throw new FidoSecurityError(
                    "Security error: rpId must not be a registrable domain suffix!");
        }
        return rpId;
    }


}
