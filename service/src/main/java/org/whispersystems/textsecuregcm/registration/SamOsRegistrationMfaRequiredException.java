/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration;

import java.util.List;

public class SamOsRegistrationMfaRequiredException extends RuntimeException {

  private final int compatibilityStatus;
  private final List<String> methods;

  SamOsRegistrationMfaRequiredException(final String message, final int compatibilityStatus,
      final List<String> methods) {
    super(message);
    this.compatibilityStatus = compatibilityStatus;
    this.methods = List.copyOf(methods);
  }

  public int compatibilityStatus() {
    return compatibilityStatus;
  }

  public List<String> methods() {
    return methods;
  }
}
