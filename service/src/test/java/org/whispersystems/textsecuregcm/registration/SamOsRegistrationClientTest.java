/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.protobuf.Timestamp;
import com.securityphone.contracts.v1.BeginRegistrationRequest;
import com.securityphone.contracts.v1.BeginRegistrationResponse;
import com.securityphone.contracts.v1.CompleteRegistrationRequest;
import com.securityphone.contracts.v1.CompleteRegistrationResponse;
import com.securityphone.contracts.v1.RegistrationBoundaryServiceGrpc;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SamOsRegistrationClientTest {

  private static final String SERVER_NAME = SamOsRegistrationClientTest.class.getName();
  private Server server;
  private ManagedChannel channel;

  @BeforeEach
  void setUp() throws Exception {
    server = InProcessServerBuilder.forName(SERVER_NAME)
        .directExecutor()
        .addService(new RegistrationBoundaryServiceGrpc.RegistrationBoundaryServiceImplBase() {
          @Override
          public void beginRegistration(final BeginRegistrationRequest request,
              final StreamObserver<BeginRegistrationResponse> responseObserver) {
            responseObserver.onNext(BeginRegistrationResponse.newBuilder()
                .setRegistrationId("registration-1")
                .setRegistrationGrant("signed-grant")
                .setExpiresAt(Timestamp.newBuilder().setSeconds(1234).build())
                .build());
            responseObserver.onCompleted();
          }

          @Override
          public void completeRegistration(final CompleteRegistrationRequest request,
              final StreamObserver<CompleteRegistrationResponse> responseObserver) {
            if (request.getMfaAssertion().isBlank()) {
              final Metadata trailers = new Metadata();
              trailers.put(Metadata.Key.of("security-phone-http-status", Metadata.ASCII_STRING_MARSHALLER), "441");
              trailers.put(Metadata.Key.of("security-phone-mfa-methods", Metadata.ASCII_STRING_MARSHALLER),
                  "webauthn,totp");
              responseObserver.onError(Status.FAILED_PRECONDITION
                  .withDescription("MFA is required")
                  .asRuntimeException(trailers));
              return;
            }

            responseObserver.onNext(CompleteRegistrationResponse.newBuilder()
                .setAccountId("account-1")
                .setAci("8acb07eb-beb9-4f3b-93f2-a54a310495a7")
                .setPni("00d2be6a-6328-4d45-b1bb-70f6549d2c8f")
                .setDeviceSlot(1)
                .setRegisteredAt(Timestamp.newBuilder().setSeconds(2345).build())
                .build());
            responseObserver.onCompleted();
          }
        })
        .build()
        .start();
    channel = InProcessChannelBuilder.forName(SERVER_NAME).directExecutor().build();
  }

  @AfterEach
  void tearDown() {
    channel.shutdownNow();
    server.shutdownNow();
  }

  @Test
  void exchangesOidcPkceForShortLivedGrant() {
    final SamOsRegistrationClient client = new SamOsRegistrationClient(channel, Duration.ofSeconds(2));

    final SamOsRegistrationClient.BeginResult result = client.beginRegistration(
        new SamOsRegistrationClient.BeginCommand(
            "subject-1", "ENTERPRISE", "attestation", "org-1", "user-1", "code", "v".repeat(43),
            "https://app.example/callback"));

    assertEquals("registration-1", result.registrationId());
    assertEquals("signed-grant", result.registrationGrant());
    assertEquals(Instant.ofEpochSecond(1234), result.expiresAt());
  }

  @Test
  void completesRegistrationWithOpaqueIdentifiers() {
    final SamOsRegistrationClient client = new SamOsRegistrationClient(channel, Duration.ofSeconds(2));

    final SamOsRegistrationClient.CompleteResult result = client.completeRegistration(
        new SamOsRegistrationClient.CompleteCommand(
            "registration-1", "signed-grant", new byte[]{1}, new byte[]{2}, "webauthn", "assertion"));

    assertEquals("account-1", result.accountId());
    assertEquals(UUID.fromString("8acb07eb-beb9-4f3b-93f2-a54a310495a7"), result.aci());
    assertEquals(UUID.fromString("00d2be6a-6328-4d45-b1bb-70f6549d2c8f"), result.pni());
    assertEquals(1, result.deviceSlot());
    assertEquals(Instant.ofEpochSecond(2345), result.registeredAt());
  }

  @Test
  void mapsSamOsMfaRequirementToCompatibilityStatus441() {
    final SamOsRegistrationClient client = new SamOsRegistrationClient(channel, Duration.ofSeconds(2));

    final SamOsRegistrationMfaRequiredException exception = assertThrows(
        SamOsRegistrationMfaRequiredException.class,
        () -> client.completeRegistration(new SamOsRegistrationClient.CompleteCommand(
            "registration-1", "signed-grant", new byte[]{1}, new byte[]{2}, "", "")));

    assertEquals(441, exception.compatibilityStatus());
    assertEquals(List.of("webauthn", "totp"), exception.methods());
  }
}
