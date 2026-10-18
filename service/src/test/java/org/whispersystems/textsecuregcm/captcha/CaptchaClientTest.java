/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.captcha;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class CaptchaClientTest {

  @Test
  void unavailableClientRejectsEveryToken() throws IOException {
    final CaptchaClient client = CaptchaClient.unavailable();

    assertThat(client.scheme()).isEqualTo("unavailable");
    assertThat(client.validSiteKeys(Action.REGISTRATION)).isEmpty();
    assertThat(client.verify(Optional.empty(), "noop", Action.REGISTRATION, "noop", "127.0.0.1", null)
        .isValid()).isFalse();
  }
}
