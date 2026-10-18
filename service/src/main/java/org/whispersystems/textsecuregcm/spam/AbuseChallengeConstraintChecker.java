/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import jakarta.ws.rs.container.ContainerRequestContext;
import java.util.Optional;
import org.whispersystems.textsecuregcm.storage.Account;

public final class AbuseChallengeConstraintChecker implements ChallengeConstraintChecker {

  private final AbuseClient abuseClient;

  public AbuseChallengeConstraintChecker(final AbuseClient abuseClient) {
    this.abuseClient = abuseClient;
  }

  @Override
  public ChallengeConstraints challengeConstraintsHttp(final ContainerRequestContext requestContext,
      final Account authenticatedAccount) {
    return constraints(authenticatedAccount.getAccountIdentifier().toString());
  }

  @Override
  public ChallengeConstraints challengeConstraintsGrpc(final Account authenticatedAccount) {
    return constraints(authenticatedAccount.getAccountIdentifier().toString());
  }

  private ChallengeConstraints constraints(final String subjectId) {
    final boolean approved = abuseClient.evaluate("challenge.request", subjectId, "").allowed();
    return new ChallengeConstraints(approved, Optional.empty());
  }
}
