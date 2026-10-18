/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.purchases;

import java.util.Arrays;
import java.util.Optional;

/// Legacy receipt-level identifiers retained only for numberless-account and backup credential compatibility.
/// Security Phone does not expose the consumer purchase controllers that originally issued these receipts.
public enum ReceiptLevel {
  ONE_TIME_DONATION(1L),
  ONE_TIME_GIFT_DONATION(100L),
  BACKUP_FREE(200L),
  BACKUP_PAID(201L),
  LOGIN(300L),
  LOGIN_SANDBOX(301L),
  SUBSCRIPTION_LOW(500),
  SUBSCRIPTION_MEDIUM(1000),
  SUBSCRIPTION_HIGH(2000);

  private static final ReceiptLevel[] VALUES = ReceiptLevel.values();

  private final long value;

  ReceiptLevel(final long value) {
    this.value = value;
  }

  public long getValue() {
    return value;
  }

  public static Optional<ReceiptLevel> lookupLevel(final long level) {
    return Arrays.stream(VALUES).filter(receiptLevel -> receiptLevel.value == level).findFirst();
  }
}
