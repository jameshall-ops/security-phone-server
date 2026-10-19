/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.storage.Account;

public final class AbuseRegistrationFraudChecker implements RegistrationFraudChecker {

  private final AbuseClient abuseClient;

  public AbuseRegistrationFraudChecker(final AbuseClient abuseClient) {
    this.abuseClient = abuseClient;
  }

  @Override
  public VerificationCheck checkVerificationAttempt(final ContainerRequestContext requestContext,
      final VerificationSession verificationSession, final String e164,
      final UpdateVerificationSessionRequest request) {
    requireApproval("registration.verification", e164);
    return VerificationCheck.DEFAULT;
  }

  @Override
  public VerificationCheck checkSendVerificationCodeAttempt(final ContainerRequestContext requestContext,
      final VerificationSession verificationSession, final String e164) {
    requireApproval("registration.code", e164);
    return VerificationCheck.DEFAULT;
  }

  @Override
  public void handleVerificationCompleted(final String verificationSessionId, final Account createdAccount) {
  }

  private void requireApproval(final String signalType, final String subjectId) {
    if (!abuseClient.evaluate(signalType, subjectId, "").allowed()) {
      throw new ForbiddenException("abuse review unavailable");
    }
  }
}
