/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.annotations.VisibleForTesting;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.signal.libsignal.protocol.IdentityKey;
import org.whispersystems.textsecuregcm.util.IdentityKeyAdapter;

public record SamOsCompleteRegistrationRequest(
    @NotBlank String registrationId,
    @NotBlank String registrationGrant,
    @Size(max = 32) String mfaMethod,
    @Size(max = 8192) String mfaAssertion,
    @NotNull @Valid AccountAttributes accountAttributes,
    @NotNull @Valid
    @JsonSerialize(using = IdentityKeyAdapter.Serializer.class)
    @JsonDeserialize(using = IdentityKeyAdapter.Deserializer.class)
    IdentityKey aciIdentityKey,
    @NotNull @Valid DeviceActivationRequest deviceActivationRequest) {

  @VisibleForTesting
  @AssertTrue
  boolean isEverySignedKeyValid() {
    return deviceActivationRequest != null
        && aciIdentityKey != null
        && deviceActivationRequest.aciSignedPreKey() != null
        && deviceActivationRequest.aciPqLastResortPreKey() != null
        && PreKeySignatureValidator.validatePreKeySignatures(
            aciIdentityKey,
            List.of(deviceActivationRequest.aciSignedPreKey(), deviceActivationRequest.aciPqLastResortPreKey()),
            null,
            "sam-os-register");
  }

  @VisibleForTesting
  @AssertTrue
  boolean hasNoPhoneIdentityMaterial() {
    return deviceActivationRequest != null
        && deviceActivationRequest.pniSignedPreKey().isEmpty()
        && deviceActivationRequest.pniPqLastResortPreKey().isEmpty()
        && (accountAttributes == null || accountAttributes.getPhoneNumberIdentityRegistrationId().isEmpty());
  }

  @VisibleForTesting
  @AssertTrue
  boolean hasMatchingMfaFields() {
    return (mfaMethod == null || mfaMethod.isBlank()) == (mfaAssertion == null || mfaAssertion.isBlank());
  }

  @VisibleForTesting
  @AssertTrue
  boolean isExactlyOneMessageDeliveryChannel() {
    if (deviceActivationRequest == null || accountAttributes == null) {
      return false;
    }
    if (accountAttributes.getFetchesMessages()) {
      return deviceActivationRequest.apnToken().isEmpty() && deviceActivationRequest.gcmToken().isEmpty();
    }
    return deviceActivationRequest.apnToken().isPresent() ^ deviceActivationRequest.gcmToken().isPresent();
  }
}
