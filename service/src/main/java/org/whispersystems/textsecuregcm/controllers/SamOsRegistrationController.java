/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Optional;
import org.whispersystems.textsecuregcm.auth.BasicAuthorizationHeader;
import org.whispersystems.textsecuregcm.entities.AccountCreationResponse;
import org.whispersystems.textsecuregcm.entities.SamOsBeginRegistrationRequest;
import org.whispersystems.textsecuregcm.entities.SamOsCompleteRegistrationRequest;
import org.whispersystems.textsecuregcm.entities.SamOsRegistrationResponses;
import org.whispersystems.textsecuregcm.registration.SamOsRegistrationClient;
import org.whispersystems.textsecuregcm.registration.SamOsRegistrationMfaRequiredException;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DeviceCapability;
import org.whispersystems.textsecuregcm.storage.DeviceIdentityInfo;
import org.whispersystems.textsecuregcm.storage.DeviceSpec;
import org.whispersystems.textsecuregcm.util.HeaderUtils;

@Path("/v1/registration/sam-os")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class SamOsRegistrationController {

  private final Optional<SamOsRegistrationClient> client;
  private final AccountsManager accountsManager;

  public SamOsRegistrationController(final Optional<SamOsRegistrationClient> client,
      final AccountsManager accountsManager) {
    this.client = client;
    this.accountsManager = accountsManager;
  }

  @POST
  @Path("/begin")
  @Operation(summary = "Exchange a SAM OS OIDC authorization code and PKCE verifier for a short-lived registration grant")
  public SamOsRegistrationResponses.Begin begin(@NotNull @Valid final SamOsBeginRegistrationRequest request) {
    final SamOsRegistrationClient.BeginResult result;
    try {
      result = requireClient().beginRegistration(new SamOsRegistrationClient.BeginCommand(
          request.subject(), request.tier(), request.deviceAttestation(), request.organizationId(), request.userId(),
          request.authorizationCode(), request.codeVerifier(), request.redirectUri()));
    } catch (final StatusRuntimeException e) {
      throw mapUpstreamFailure(e);
    }
    return new SamOsRegistrationResponses.Begin(
        result.registrationId(), result.registrationGrant(), result.expiresAt());
  }

  @POST
  @Path("/complete")
  @Operation(summary = "Create a numberless Security Phone account from a SAM OS-governed registration grant")
  public SamOsRegistrationResponses.Complete complete(
      @HeaderParam(HttpHeaders.AUTHORIZATION) @NotNull final BasicAuthorizationHeader authorizationHeader,
      @HeaderParam(HeaderUtils.X_SIGNAL_AGENT) final String signalAgent,
      @HeaderParam(HttpHeaders.USER_AGENT) final String userAgent,
      @NotNull @Valid final SamOsCompleteRegistrationRequest request) {

    if (!(request.accountAttributes().getCapabilities() == null
        ? java.util.Set.<DeviceCapability>of()
        : request.accountAttributes().getCapabilities())
        .containsAll(DeviceCapability.CAPABILITIES_REQUIRED_FOR_NEW_DEVICES)) {
      throw new WebApplicationException("Missing required device capability", 499);
    }
    if (request.accountAttributes().recoveryPassword().isEmpty()) {
      throw new WebApplicationException("Recovery password is required", 422);
    }

    final SamOsRegistrationClient.CompleteResult result;
    try {
      result = requireClient().completeRegistration(new SamOsRegistrationClient.CompleteCommand(
          request.registrationId(),
          request.registrationGrant(),
          request.aciIdentityKey().serialize(),
          serializeSignedPreKey(request),
          request.mfaMethod() == null ? "" : request.mfaMethod(),
          request.mfaAssertion() == null ? "" : request.mfaAssertion()));
    } catch (final SamOsRegistrationMfaRequiredException e) {
      throw new WebApplicationException(Response.status(e.compatibilityStatus())
          .entity(new SamOsRegistrationResponses.MfaRequired("mfa_required", e.methods()))
          .type(MediaType.APPLICATION_JSON_TYPE)
          .build());
    } catch (final StatusRuntimeException e) {
      throw mapUpstreamFailure(e);
    }

    final Account account = accountsManager.createGovernedNumberless(
        result.aci(),
        request.accountAttributes(),
        request.aciIdentityKey(),
        new DeviceSpec(
            request.accountAttributes().getName(),
            authorizationHeader.getPassword(),
            signalAgent,
            request.accountAttributes().getCapabilities(),
            new DeviceIdentityInfo(
                request.accountAttributes().getRegistrationId(),
                request.deviceActivationRequest().aciSignedPreKey(),
                request.deviceActivationRequest().aciPqLastResortPreKey()),
            Optional.empty(),
            request.accountAttributes().getFetchesMessages(),
            request.deviceActivationRequest().apnToken(),
            request.deviceActivationRequest().gcmToken()),
        userAgent);

    return new SamOsRegistrationResponses.Complete(
        new AccountCreationResponse(AccountIdentityResponseBuilder.fromAccount(account), false),
        result.pni(),
        result.deviceSlot(),
        result.registeredAt());
  }

  private SamOsRegistrationClient requireClient() {
    return client.orElseThrow(() -> new WebApplicationException("SAM OS registration is not configured", 503));
  }

  private static WebApplicationException mapUpstreamFailure(final StatusRuntimeException error) {
    if (error.getStatus().getCode() == Status.Code.PERMISSION_DENIED
        || error.getStatus().getCode() == Status.Code.UNAUTHENTICATED) {
      return new WebApplicationException("SAM OS registration was denied", 403);
    }
    if (error.getStatus().getCode() == Status.Code.RESOURCE_EXHAUSTED) {
      return new WebApplicationException("Security Phone device limit reached", 409);
    }
    return new WebApplicationException("SAM OS registration is temporarily unavailable", 503);
  }

  private static byte[] serializeSignedPreKey(final SamOsCompleteRegistrationRequest request) {
    final byte[] publicKey = request.deviceActivationRequest().aciSignedPreKey().serializedPublicKey();
    final byte[] signature = request.deviceActivationRequest().aciSignedPreKey().signature();
    try {
      final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (DataOutputStream output = new DataOutputStream(bytes)) {
        output.writeLong(request.deviceActivationRequest().aciSignedPreKey().keyId());
        output.writeInt(publicKey.length);
        output.write(publicKey);
        output.writeInt(signature.length);
        output.write(signature);
      }
      return bytes.toByteArray();
    } catch (final IOException impossible) {
      throw new AssertionError(impossible);
    }
  }
}
