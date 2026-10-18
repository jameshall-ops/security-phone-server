/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import javax.annotation.Nullable;

public record AbuseServiceConfiguration(@Nullable String target, Duration timeout) {

  @JsonCreator
  public AbuseServiceConfiguration(@JsonProperty("target") @Nullable final String target,
      @JsonProperty("timeout") @Nullable final Duration timeout) {
    this.target = target;
    this.timeout = timeout == null ? Duration.ofSeconds(2) : timeout;
  }

  public boolean configured() {
    return target != null && !target.isBlank();
  }
}
