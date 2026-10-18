/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import jakarta.annotation.Nullable;

public final class AbuseRegistrationRecoveryChecker implements RegistrationRecoveryChecker {

  private final AbuseClient abuseClient;

  public AbuseRegistrationRecoveryChecker(final AbuseClient abuseClient) {
    this.abuseClient = abuseClient;
  }

  @Override
  public boolean checkRegistrationRecoveryAttempt(final String e164, @Nullable final String userAgent,
      @Nullable final String acceptLanguage, @Nullable final String mostRecentProxy) {
    return abuseClient.evaluate("registration.recovery", e164, "").allowed();
  }
}
