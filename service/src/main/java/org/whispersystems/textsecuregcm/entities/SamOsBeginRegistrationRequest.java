/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SamOsBeginRegistrationRequest(
    @NotBlank String subject,
    @NotBlank String tier,
    @NotBlank String deviceAttestation,
    @NotBlank String organizationId,
    @NotBlank String userId,
    @NotBlank String authorizationCode,
    @NotBlank @Size(min = 43, max = 128) String codeVerifier,
    @NotBlank String redirectUri) {
}
