/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import javax.annotation.Nullable;

public record SamOsRegistrationServiceConfiguration(@Nullable String host, int port,
                                                     @Nullable String trustedCaCertificate, Duration timeout) {

  @JsonCreator
  public SamOsRegistrationServiceConfiguration(
      @JsonProperty("host") @Nullable final String host,
      @JsonProperty("port") final int port,
      @JsonProperty("trustedCaCertificate") @Nullable final String trustedCaCertificate,
      @JsonProperty("timeout") @Nullable final Duration timeout) {
    this.host = host;
    this.port = port == 0 ? 443 : port;
    this.trustedCaCertificate = trustedCaCertificate;
    this.timeout = timeout == null ? Duration.ofSeconds(5) : timeout;
    if (configured() && (trustedCaCertificate == null || trustedCaCertificate.isBlank())) {
      throw new IllegalArgumentException("SAM OS registration requires a pinned CA certificate");
    }
  }

  public boolean configured() {
    return host != null && !host.isBlank();
  }
}
