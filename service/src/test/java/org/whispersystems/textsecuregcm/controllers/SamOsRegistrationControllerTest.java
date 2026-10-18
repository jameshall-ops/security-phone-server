/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import jakarta.ws.rs.WebApplicationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.whispersystems.textsecuregcm.auth.BasicAuthorizationHeader;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.entities.DeviceActivationRequest;
import org.whispersystems.textsecuregcm.entities.SamOsBeginRegistrationRequest;
import org.whispersystems.textsecuregcm.entities.SamOsCompleteRegistrationRequest;
import org.whispersystems.textsecuregcm.registration.SamOsRegistrationClient;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DeviceCapability;
import org.whispersystems.textsecuregcm.storage.DeviceSpec;
import org.whispersystems.textsecuregcm.tests.util.KeysHelper;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;

class SamOsRegistrationControllerTest {

  private static final UUID ACI = UUID.fromString("8acb07eb-beb9-4f3b-93f2-a54a310495a7");
  private static final UUID PNI = UUID.fromString("00d2be6a-6328-4d45-b1bb-70f6549d2c8f");

  private final SamOsRegistrationClient client = mock(SamOsRegistrationClient.class);
  private final AccountsManager accountsManager = mock(AccountsManager.class);
  private final SamOsRegistrationController controller =
      new SamOsRegistrationController(Optional.of(client), accountsManager);

  @BeforeEach
  void setUp() {
    when(client.beginRegistration(any())).thenReturn(new SamOsRegistrationClient.BeginResult(
        "registration-1", "grant", Instant.ofEpochSecond(100)));
    when(client.completeRegistration(any())).thenReturn(new SamOsRegistrationClient.CompleteResult(
        "account-1", ACI, PNI, 1, Instant.ofEpochSecond(200)));
    when(accountsManager.createGovernedNumberless(any(), any(), any(), any(), any()))
        .thenAnswer(invocation -> {
          final Account account = new Account();
          account.setAccountIdentifier(invocation.getArgument(0));
          account.setIdentityKey(invocation.getArgument(2));
          final DeviceSpec deviceSpec = invocation.getArgument(3);
          account.addDevice(deviceSpec.toDevice((byte) 1, Clock.systemUTC(), invocation.getArgument(2)));
          account.setAuthCredentialSalt(TestRandomUtil.nextBytes(32));
          return account;
        });
  }

  @Test
  void beginsRegistrationThroughSamOs() {
    final var response = controller.begin(new SamOsBeginRegistrationRequest(
        "subject-1", "ENTERPRISE", "attestation", "org-1", "user-1", "code", "v".repeat(43),
        "https://app.example/callback"));

    assertEquals("registration-1", response.registrationId());
    assertEquals("grant", response.registrationGrant());
  }

  @Test
  void completesGovernedNumberlessAccountCreation() throws Exception {
    final ECKeyPair keyPair = ECKeyPair.generate();
    final AccountAttributes attributes = new AccountAttributes(
        true,
        1,
        null,
        "device".getBytes(StandardCharsets.UTF_8),
        null,
        false,
        DeviceCapability.CAPABILITIES_REQUIRED_FOR_NEW_DEVICES,
        TestRandomUtil.nextBytes(32));
    final SamOsCompleteRegistrationRequest request = new SamOsCompleteRegistrationRequest(
        "registration-1",
        "grant",
        "webauthn",
        "assertion",
        attributes,
        new IdentityKey(keyPair.getPublicKey()),
        new DeviceActivationRequest(
            KeysHelper.signedECPreKey(1, keyPair),
            Optional.empty(),
            KeysHelper.signedKEMPreKey(3, keyPair),
            Optional.empty(),
            Optional.empty(),
            Optional.empty()));
    final BasicAuthorizationHeader authorization = BasicAuthorizationHeader.fromString("Basic "
        + Base64.getEncoder().encodeToString("sam-user:device-password".getBytes(StandardCharsets.UTF_8)));

    final var response = controller.complete(authorization, "SecurityPhone-Test", "SecurityPhone-Test", request);

    assertEquals(ACI, response.account().identityResponse().uuid());
    assertEquals(PNI, response.pni());
    assertEquals(1, response.deviceSlot());
    assertFalse(response.account().identityResponse().number().isPresent());
    final ArgumentCaptor<SamOsRegistrationClient.CompleteCommand> command =
        ArgumentCaptor.forClass(SamOsRegistrationClient.CompleteCommand.class);
    verify(client).completeRegistration(command.capture());
    assertEquals("registration-1", command.getValue().registrationId());
    verify(accountsManager).createGovernedNumberless(any(), any(), any(), any(), any());
  }

  @Test
  void failsClosedWhenSamOsRegistrationIsNotConfigured() {
    final SamOsRegistrationController unconfigured =
        new SamOsRegistrationController(Optional.empty(), accountsManager);

    final WebApplicationException exception = assertThrows(WebApplicationException.class,
        () -> unconfigured.begin(new SamOsBeginRegistrationRequest(
            "subject-1", "ENTERPRISE", "attestation", "org-1", "user-1", "code", "v".repeat(43),
            "https://app.example/callback")));

    assertEquals(503, exception.getResponse().getStatus());
  }
}
