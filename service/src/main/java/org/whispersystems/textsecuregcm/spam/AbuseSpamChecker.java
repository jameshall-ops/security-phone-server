/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import io.grpc.Status;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.util.Optional;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.storage.Account;

public final class AbuseSpamChecker implements SpamChecker {

  private final AbuseClient abuseClient;

  public AbuseSpamChecker(final AbuseClient abuseClient) {
    this.abuseClient = abuseClient;
  }

  @Override
  public SpamCheckResult<Response> checkForIndividualRecipientSpamHttp(final MessageType messageType,
      final ContainerRequestContext requestContext,
      final Optional<org.whispersystems.textsecuregcm.auth.AuthenticatedDevice> maybeSource,
      final Optional<Account> maybeDestination,
      final ServiceIdentifier destinationIdentifier) {
    return httpResult("message.individual." + messageType.name(), destinationIdentifier.toString());
  }

  @Override
  public SpamCheckResult<Response> checkForMultiRecipientSpamHttp(final MessageType messageType,
      final ContainerRequestContext requestContext) {
    return httpResult("message.multi." + messageType.name(), "multi-recipient");
  }

  @Override
  public SpamCheckResult<GrpcChallengeResponse> checkForIndividualRecipientSpamGrpc(final MessageType messageType,
      final Optional<org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice> maybeSource,
      final Optional<Account> maybeDestination,
      final ServiceIdentifier destinationIdentifier) {
    return grpcResult("message.individual." + messageType.name(), destinationIdentifier.toString());
  }

  @Override
  public SpamCheckResult<GrpcChallengeResponse> checkForMultiRecipientSpamGrpc(final MessageType messageType) {
    return grpcResult("message.multi." + messageType.name(), "multi-recipient");
  }

  private SpamCheckResult<Response> httpResult(final String signalType, final String subjectId) {
    if (allowed(signalType, subjectId)) {
      return new SpamCheckResult<>(Optional.empty(), Optional.empty());
    }

    return new SpamCheckResult<>(Optional.of(Response.status(Response.Status.SERVICE_UNAVAILABLE).build()),
        Optional.empty());
  }

  private SpamCheckResult<GrpcChallengeResponse> grpcResult(final String signalType, final String subjectId) {
    if (allowed(signalType, subjectId)) {
      return new SpamCheckResult<>(Optional.empty(), Optional.empty());
    }

    return new SpamCheckResult<>(Optional.of(GrpcChallengeResponse.withStatusException(
        Status.UNAVAILABLE.withDescription("abuse review unavailable").asRuntimeException())), Optional.empty());
  }

  private boolean allowed(final String signalType, final String subjectId) {
    return abuseClient.evaluate(signalType, subjectId, "").allowed();
  }
}
