package de.cotech.hw.fido2.internal.utils;


import de.cotech.hw.fido2.exceptions.FidoSecurityError;
import org.junit.Test;

import static org.junit.Assert.assertEquals;


@SuppressWarnings("WeakerAccess")
public class RelyingPartyIdUtilsTest {
    RelyingPartyIdUtils relyingPartyIdUtils = new RelyingPartyIdUtils();

    @Test
    public void nul() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://example.org", null);
        assertEquals("example.org", rpId);
    }

    @Test
    public void nul_subdomain() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://sub.example.org", null);
        assertEquals("sub.example.org", rpId);
    }

    @Test
    public void parent_domain() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://sub.example.org", "example.org");
        assertEquals("example.org", rpId);
    }

    @Test
    public void parent_subdomain() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://sub.sub.example.org", "sub.example.org");
        assertEquals("sub.example.org", rpId);
    }

    @Test
    public void same_domain() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://example.org", "example.org");
        assertEquals("example.org", rpId);
    }

    @Test(expected = FidoSecurityError.class)
    public void same_subdomain() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://example.org", "sub.example.org");
        assertEquals("sub.example.org", rpId);
    }

    @Test(expected = FidoSecurityError.class)
    public void incorrect_domain() throws Exception {
        relyingPartyIdUtils.determineRelyingPartyId("https://example.org", "not-example.org");
    }

    @Test(expected = FidoSecurityError.class)
    public void incorrect_subdomain() throws Exception {
        relyingPartyIdUtils.determineRelyingPartyId("https://example.org", "wrong.not-example.org");
    }

    @Test(expected = FidoSecurityError.class)
    public void incorrect_prefix() throws Exception {
        relyingPartyIdUtils.determineRelyingPartyId("https://example.org", "notexample.org");
    }

    @Test
    public void public_suffix() throws Exception {
        String rpId = relyingPartyIdUtils.determineRelyingPartyId("https://sub.example.co.uk", "example.co.uk");
        assertEquals("example.co.uk", rpId);
    }

    @Test(expected = FidoSecurityError.class)
    public void public_suffix_bad() throws Exception {
        relyingPartyIdUtils.determineRelyingPartyId("https://example.org", "org");
    }

    @Test(expected = FidoSecurityError.class)
    public void public_suffix_bad_two() throws Exception {
        relyingPartyIdUtils.determineRelyingPartyId("https://example.github.io", "github.io");
    }

    @Test(expected = FidoSecurityError.class)
    public void public_suffix_bad_three() throws Exception {
        relyingPartyIdUtils.determineRelyingPartyId("https://sub.co.uk", "co.uk");
    }
}
