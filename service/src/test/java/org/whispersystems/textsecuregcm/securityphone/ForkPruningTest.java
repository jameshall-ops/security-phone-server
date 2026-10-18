/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.securityphone;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ForkPruningTest {

  private static final Path MAIN_JAVA = Path.of("src/main/java/org/whispersystems/textsecuregcm");

  @Test
  void paymentDonationAndBadgeEntryPointsAreAbsent() {
    final List<Path> forbiddenEntryPoints = List.of(
        MAIN_JAVA.resolve("controllers/SubscriptionController.java"),
        MAIN_JAVA.resolve("controllers/OneTimeDonationController.java"),
        MAIN_JAVA.resolve("controllers/DonationController.java"),
        MAIN_JAVA.resolve("controllers/PaymentsController.java"),
        MAIN_JAVA.resolve("grpc/SubscriptionsGrpcService.java"),
        MAIN_JAVA.resolve("grpc/OneTimeDonationsGrpcService.java"),
        MAIN_JAVA.resolve("grpc/DonationsGrpcService.java"),
        MAIN_JAVA.resolve("grpc/PaymentsGrpcService.java"),
        MAIN_JAVA.resolve("grpc/LoginPurchaseGrpcService.java"),
        MAIN_JAVA.resolve("controllers/LoginPurchaseController.java"));

    assertThat(forbiddenEntryPoints).allMatch(path -> !Files.exists(path),
        "payment, donation, and badge entry points must be removed");
  }

  @Test
  void serverDoesNotLoadPrivateSpamFilterOrPermitNoopCaptcha() throws IOException {
    final String serviceSource = Files.readString(MAIN_JAVA.resolve("WhisperServerService.java"));
    final String captchaSource = Files.readString(MAIN_JAVA.resolve("captcha/CaptchaClient.java"));

    assertThat(serviceSource)
        .doesNotContain("ServiceLoader.load(SpamFilter.class)")
        .doesNotContain("SpamChecker.noop()")
        .doesNotContain("CaptchaClient.noop()");
    assertThat(captchaSource).doesNotContain("alwaysValid()");
    assertThat(MAIN_JAVA.resolve("spam/AbuseClient.java")).exists();
  }

  @Test
  void sampleConfigurationContainsNoCommerceOrBadgeKeys() throws IOException {
    final String sampleConfiguration = Files.readString(Path.of("config/sample.yml"));

    assertThat(sampleConfiguration)
        .doesNotContain("subscription:")
        .doesNotContain("oneTimeDonations:")
        .doesNotContain("loginPurchase:")
        .doesNotContain("badges:")
        .doesNotContain("stripe:")
        .doesNotContain("braintree:");
  }
}
