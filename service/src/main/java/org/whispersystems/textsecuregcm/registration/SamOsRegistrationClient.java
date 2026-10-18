/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration;

import com.google.protobuf.ByteString;
import com.securityphone.contracts.v1.BeginRegistrationRequest;
import com.securityphone.contracts.v1.BeginRegistrationResponse;
import com.securityphone.contracts.v1.CompleteRegistrationRequest;
import com.securityphone.contracts.v1.CompleteRegistrationResponse;
import com.securityphone.contracts.v1.RegistrationBoundaryServiceGrpc;
import io.dropwizard.lifecycle.Managed;
import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.TlsChannelCredentials;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * TLS client for the SAM OS-owned registration boundary. The wire contract is the only dependency crossing the AGPL
 * boundary; no SAM OS implementation is imported into this fork.
 */
public class SamOsRegistrationClient implements Managed {

  private static final Metadata.Key<String> HTTP_STATUS_TRAILER =
      Metadata.Key.of("security-phone-http-status", Metadata.ASCII_STRING_MARSHALLER);
  private static final Metadata.Key<String> MFA_METHODS_TRAILER =
      Metadata.Key.of("security-phone-mfa-methods", Metadata.ASCII_STRING_MARSHALLER);

  private final ManagedChannel channel;
  private final RegistrationBoundaryServiceGrpc.RegistrationBoundaryServiceBlockingStub stub;
  private final Duration timeout;

  public SamOsRegistrationClient(final String host, final int port, final String trustedCaCertificate,
      final Duration timeout) throws IOException {
    try (ByteArrayInputStream certificateInputStream =
             new ByteArrayInputStream(trustedCaCertificate.getBytes(StandardCharsets.UTF_8))) {
      final ChannelCredentials credentials = TlsChannelCredentials.newBuilder()
          .trustManager(certificateInputStream)
          .build();
      this.channel = Grpc.newChannelBuilderForAddress(host, port, credentials)
          .idleTimeout(1, TimeUnit.MINUTES)
          .build();
    }
    this.stub = RegistrationBoundaryServiceGrpc.newBlockingStub(channel);
    this.timeout = timeout;
  }

  SamOsRegistrationClient(final ManagedChannel channel, final Duration timeout) {
    this.channel = channel;
    this.stub = RegistrationBoundaryServiceGrpc.newBlockingStub(channel);
    this.timeout = timeout;
  }

  public BeginResult beginRegistration(final BeginCommand command) {
    final BeginRegistrationResponse response = stub.withDeadlineAfter(timeout.toMillis(), TimeUnit.MILLISECONDS)
        .beginRegistration(BeginRegistrationRequest.newBuilder()
            .setSubject(command.subject())
            .setTier(command.tier())
            .setDeviceAttestation(command.deviceAttestation())
            .setOrganizationId(command.organizationId())
            .setUserId(command.userId())
            .setAuthorizationCode(command.authorizationCode())
            .setCodeVerifier(command.codeVerifier())
            .setRedirectUri(command.redirectUri())
            .build());

    return new BeginResult(
        response.getRegistrationId(),
        response.getRegistrationGrant(),
        Instant.ofEpochSecond(response.getExpiresAt().getSeconds(), response.getExpiresAt().getNanos()));
  }

  public CompleteResult completeRegistration(final CompleteCommand command) {
    try {
      final CompleteRegistrationResponse response = stub.withDeadlineAfter(timeout.toMillis(), TimeUnit.MILLISECONDS)
          .completeRegistration(CompleteRegistrationRequest.newBuilder()
              .setRegistrationId(command.registrationId())
              .setRegistrationGrant(command.registrationGrant())
              .setIdentityKey(ByteString.copyFrom(command.identityKey()))
              .setSignedPreKey(ByteString.copyFrom(command.signedPreKey()))
              .setMfaMethod(command.mfaMethod())
              .setMfaAssertion(command.mfaAssertion())
              .build());

      return new CompleteResult(
          response.getAccountId(),
          UUID.fromString(response.getAci()),
          UUID.fromString(response.getPni()),
          response.getDeviceSlot(),
          Instant.ofEpochSecond(response.getRegisteredAt().getSeconds(), response.getRegisteredAt().getNanos()));
    } catch (final StatusRuntimeException e) {
      final Metadata trailers = e.getTrailers();
      final String compatibilityStatus = trailers == null ? null : trailers.get(HTTP_STATUS_TRAILER);
      if (e.getStatus().getCode() == Status.Code.FAILED_PRECONDITION && "441".equals(compatibilityStatus)) {
        final String methods = trailers.get(MFA_METHODS_TRAILER);
        throw new SamOsRegistrationMfaRequiredException(
            e.getStatus().getDescription(),
            441,
            methods == null || methods.isBlank() ? List.of() : Arrays.asList(methods.split(",")));
      }
      throw e;
    }
  }

  @Override
  public void start() {
  }

  @Override
  public void stop() throws InterruptedException {
    channel.shutdown();
    if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
      channel.shutdownNow();
    }
  }

  public record BeginCommand(String subject, String tier, String deviceAttestation, String organizationId,
                             String userId, String authorizationCode, String codeVerifier, String redirectUri) {
  }

  public record BeginResult(String registrationId, String registrationGrant, Instant expiresAt) {
  }

  public record CompleteCommand(String registrationId, String registrationGrant, byte[] identityKey,
                                byte[] signedPreKey, String mfaMethod, String mfaAssertion) {
  }

  public record CompleteResult(String accountId, UUID aci, UUID pni, int deviceSlot, Instant registeredAt) {
  }
}
