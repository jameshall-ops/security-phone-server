/*
 * Copyright 2026 Security Television Network
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

/** Privacy-preserving bucketing for persisted device activity timestamps. */
public final class LastSeenPrivacy {

  private static final Duration BUCKET = Duration.ofDays(7);

  private LastSeenPrivacy() {
  }

  /**
   * Returns the start of the account's current seven-day bucket.
   *
   * <p>The account identifier supplies a stable offset so writes do not cluster on a shared boundary. The result does
   * not retain the day or time of the request that caused the update.</p>
   */
  public static long bucketStartMillis(final UUID accountIdentifier, final Clock clock) {
    final long bucketSeconds = BUCKET.toSeconds();
    final long accountOffsetSeconds =
        Util.ensureNonNegativeLong(accountIdentifier.getLeastSignificantBits()) % bucketSeconds;
    // Use Clock#millis rather than Clock#instant so existing storage tests and integrations that provide a
    // millisecond-only clock remain compatible. The persisted bucket is second-aligned in either case.
    final long currentEpochSeconds = Math.floorDiv(clock.millis(), 1_000L);
    final long bucketNumber = Math.floorDiv(currentEpochSeconds - accountOffsetSeconds, bucketSeconds);
    final long bucketStartSeconds = Math.addExact(
        Math.multiplyExact(bucketNumber, bucketSeconds), accountOffsetSeconds);

    return Math.multiplyExact(bucketStartSeconds, 1_000L);
  }
}
