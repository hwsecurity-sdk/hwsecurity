/*
 * Adapted to Java from OkHttp
 * https://github.com/square/okhttp/blob/master/okhttp/src/main/kotlin/okhttp3/internal/publicsuffix/PublicSuffixDatabase.kt
 *
 * Copyright (C) 2017 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.cotech.hw.fido2.internal.utils;


import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.UnsupportedEncodingException;
import java.net.IDN;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;

import androidx.annotation.Nullable;
import de.cotech.hw.util.HwTimber;


class PublicSuffixDatabase {
    // Must be an absolute path to work after Proguard optimizations!
    private static final String PUBLIC_SUFFIX_RESOURCE = "/de/cotech/hw/fido2/internal/utils/publicsuffixes.gz";
    private static final byte[] WILDCARD_LABEL = new byte[] { '*' };
    private static final char EXCEPTION_MARKER = '!';

    private AtomicBoolean listRead = new AtomicBoolean(false);
    private CountDownLatch readCompleteLatch = new CountDownLatch(1);

    private byte[] publicSuffixListBytes;
    private byte[] publicSuffixExceptionListBytes;

    /**
     * Returns the effective top-level domain plus one (eTLD+1) by referencing the public suffix
     * list.
     * Returns null if the domain is a public suffix or a private address.
     * <p>
     * Here are some examples:
     * <p>
     * ```
     * assertEquals("google.com", getEffectiveTldPlusOne("google.com"));
     * assertEquals("google.com", getEffectiveTldPlusOne("www.google.com"));
     * assertNull(getEffectiveTldPlusOne("com"));
     * assertNull(getEffectiveTldPlusOne("localhost"));
     * assertNull(getEffectiveTldPlusOne("mymacbook"));
     * ```
     *
     * @param domain
     *         A canonicalized domain. An International Domain Name (IDN) should be punycode
     *         encoded.
     */
    @Nullable
    public String getEffectiveTldPlusOne(String domain) {
        if (domain == null) {
            throw new IllegalArgumentException();
        }
        String unicodeDomain = IDN.toUnicode(domain);
        String[] domainLabels = splitDomain(unicodeDomain);

        String[] rule = findMatchingRule(domainLabels);
        if (domainLabels.length == rule.length && rule[0].charAt(0) != EXCEPTION_MARKER) {
            return null; // The domain is a public suffix.
        }

        int firstLabelOffset;
        if (rule[0].charAt(0) == EXCEPTION_MARKER) {
            // Exception rules hold the effective TLD plus one.
            firstLabelOffset = domainLabels.length - rule.length;
        } else {
            // Otherwise the rule is for a public suffix, so we must take one more label.
            firstLabelOffset = domainLabels.length - (rule.length + 1);
        }

        StringBuilder b = new StringBuilder();
        domainLabels = splitDomain(domain);
        for (int i = firstLabelOffset; i < domainLabels.length; i++) {
            b.append(domainLabels[i]);
            if (i != domainLabels.length - 1) {
                b.append('.');
            }
        }
        return b.toString();
    }


    private String[] splitDomain(String domain) {
        String[] domainLabels = domain.split("\\.");

        if (domainLabels[domainLabels.length - 1].equals("")) {
            // allow for domain name trailing dot
            return Arrays.copyOfRange(domainLabels, 0, domainLabels.length - 1);
        }

        return domainLabels;
    }

    private String[] findMatchingRule(String[] domainLabels) {
        if (!listRead.get() && listRead.compareAndSet(false, true)) {
            readTheListUninterruptibly();
        } else {
            try {
                readCompleteLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        if (publicSuffixListBytes == null || publicSuffixExceptionListBytes == null) {
            throw new IllegalStateException(
                    "Unable to load publicsuffix.gz resource from the classpath.");
        }

        // Break apart the domain into UTF-8 labels, i.e. foo.bar.com turns into [foo, bar, com].
        byte[][] domainLabelsUtf8Bytes = new byte[domainLabels.length][];
        for (int i = 0; i < domainLabels.length; i++) {
            try {
                domainLabelsUtf8Bytes[i] = domainLabels[i].getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new IllegalArgumentException(e);
            }
        }

        // Start by looking for exact matches. We start at the leftmost label. For example, foo.bar.com
        // will look like: [foo, bar, com], [bar, com], [com]. The longest matching rule wins.
        String exactMatch = null;
        for (int i = 0; i < domainLabelsUtf8Bytes.length; i++) {
            String rule = binarySearch(publicSuffixListBytes, domainLabelsUtf8Bytes, i);
            if (rule != null) {
                exactMatch = rule;
                break;
            }
        }

        // In theory, wildcard rules are not restricted to having the wildcard in the leftmost position.
        // In practice, wildcards are always in the leftmost position. For now, this implementation
        // cheats and does not attempt every possible permutation. Instead, it only considers wildcards
        // in the leftmost position. We assert this fact when we generate the public suffix file. If
        // this assertion ever fails we'll need to refactor this implementation.
        String wildcardMatch = null;
        if (domainLabelsUtf8Bytes.length > 1) {
            byte[][] labelsWithWildcard = domainLabelsUtf8Bytes.clone();
            for (int labelIndex = 0; labelIndex < labelsWithWildcard.length - 1; labelIndex++) {
                labelsWithWildcard[labelIndex] = WILDCARD_LABEL;
                String rule = binarySearch(publicSuffixListBytes, labelsWithWildcard, labelIndex);
                if (rule != null) {
                    wildcardMatch = rule;
                    break;
                }
            }
        }

        // Exception rules only apply to wildcard rules, so only try it if we matched a wildcard.
        String exception = null;
        if (wildcardMatch != null) {
            for (int labelIndex = 0; labelIndex < domainLabelsUtf8Bytes.length - 1; labelIndex++) {
                String rule = binarySearch(publicSuffixExceptionListBytes, domainLabelsUtf8Bytes,
                        labelIndex);
                if (rule != null) {
                    exception = rule;
                    break;
                }
            }
        }

        if (exception != null) {
            // Signal we've identified an exception rule.
            exception = "!" + exception;
            return exception.split("\\.");
        } else if (exactMatch == null && wildcardMatch == null) {
            return new String[] { "*" };
        }

        String[] exactRuleLabels = exactMatch != null ? exactMatch.split("\\.") : new String[0];
        String[] wildcardRuleLabels =
                wildcardMatch != null ? wildcardMatch.split("\\.") : new String[0];

        if (exactRuleLabels.length > wildcardRuleLabels.length) {
            return exactRuleLabels;
        } else {
            return wildcardRuleLabels;
        }
    }

    /**
     * Reads the public suffix list treating the operation as uninterruptible. We always want to
     * read
     * the list otherwise we'll be left in a bad state. If the thread was interrupted prior to this
     * operation, it will be re-interrupted after the list is read.
     */
    private void readTheListUninterruptibly() {
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    readTheList();
                    return;
                } catch (InterruptedIOException e) {
                    // noinspection ResultOfMethodCallIgnored, temporarily clears the interrupted state
                    Thread.interrupted();
                    interrupted = true;
                } catch (IOException e) {
                    HwTimber.e(e, "Failed to read public suffix list");
                    return;
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt(); // Retain interrupted status.
            }
        }
    }

    private void readTheList() throws IOException {
        InputStream compressedResource =
                RelyingPartyIdUtils.class.getResourceAsStream(PUBLIC_SUFFIX_RESOURCE);
        BufferedInputStream resource =
                new BufferedInputStream(new GZIPInputStream(compressedResource));

        int totalBytes = readInt(resource);
        byte[] publicSuffixListBytes = new byte[totalBytes];
        int bytesRead = resource.read(publicSuffixListBytes);
        if (bytesRead != totalBytes) {
            throw new IOException("Failed reading public suffix list!");
        }

        int totalExceptionBytes = readInt(resource);
        byte[] publicSuffixExceptionListBytes = new byte[totalExceptionBytes];
        bytesRead = resource.read(publicSuffixExceptionListBytes);
        if (bytesRead != totalExceptionBytes) {
            throw new IOException("Failed reading public suffix exception list!");
        }

        synchronized (this) {
            this.publicSuffixListBytes = publicSuffixListBytes;
            this.publicSuffixExceptionListBytes = publicSuffixExceptionListBytes;
        }

        readCompleteLatch.countDown();
    }

    private int readInt(InputStream is) throws IOException {
        int a = is.read();
        int b = is.read();
        int c = is.read();
        int d = is.read();
        return (((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff));
    }

    @Nullable
    private String binarySearch(
            byte[] dis,
            byte[][] labels,
            int labelIndex
    ) {
        int low = 0;
        int high = dis.length;
        String match = null;
        while (low < high) {
            int mid = (low + high) / 2;
            // Search for a '\n' that marks the start of a value. Don't go back past the start of the
            // array.
            while (mid > -1 && dis[mid] != '\n') {
                mid--;
            }
            mid++;

            // Now look for the ending '\n'.
            int end = 1;
            while (dis[mid + end] != '\n') {
                end++;
            }
            int publicSuffixLength = mid + end - mid;

            // Compare the bytes. Note that the file stores UTF-8 encoded bytes, so we must compare the
            // unsigned bytes.
            int compareResult;
            int currentLabelIndex = labelIndex;
            int currentLabelByteIndex = 0;
            int publicSuffixByteIndex = 0;

            boolean expectDot = false;
            while (true) {
                int byte0;
                if (expectDot) {
                    byte0 = '.';
                    expectDot = false;
                } else {
                    byte0 = labels[currentLabelIndex][currentLabelByteIndex] & 0xff;
                }

                int byte1 = dis[mid + publicSuffixByteIndex] & 0xff;

                compareResult = byte0 - byte1;
                if (compareResult != 0) {
                    break;
                }

                publicSuffixByteIndex++;
                currentLabelByteIndex++;
                if (publicSuffixByteIndex == publicSuffixLength) {
                    break;
                }

                if (labels[currentLabelIndex].length == currentLabelByteIndex) {
                    // We've exhausted our current label. Either there are more labels to compare, in which
                    // case we expect a dot as the next character. Otherwise, we've checked all our labels.
                    if (currentLabelIndex == labels.length - 1) {
                        break;
                    } else {
                        currentLabelIndex++;
                        currentLabelByteIndex = -1;
                        expectDot = true;
                    }
                }
            }

            if (compareResult < 0) {
                high = mid - 1;
            } else if (compareResult > 0) {
                low = mid + end + 1;
            } else {
                // We found a match, but are the lengths equal?
                int publicSuffixBytesLeft = publicSuffixLength - publicSuffixByteIndex;
                int labelBytesLeft = labels[currentLabelIndex].length - currentLabelByteIndex;
                for (int i = currentLabelIndex + 1; i < labels.length; i++) {
                    labelBytesLeft += labels[i].length;
                }

                if (labelBytesLeft < publicSuffixBytesLeft) {
                    high = mid - 1;
                } else if (labelBytesLeft > publicSuffixBytesLeft) {
                    low = mid + end + 1;
                } else {
                    // Found a match.
                    try {
                        match = new String(dis, mid, publicSuffixLength, "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        throw new IllegalStateException(e);
                    }
                    break;
                }
            }
        }
        return match;
    }
}
