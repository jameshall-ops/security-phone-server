/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class SamOsRegistrationResponses {

  private SamOsRegistrationResponses() {
  }

  public record Begin(String registrationId, String registrationGrant, Instant expiresAt) {
  }

  public record Complete(AccountCreationResponse account, UUID pni, int deviceSlot, Instant registeredAt) {
  }

  public record MfaRequired(String error, List<String> methods) {
  }
}
