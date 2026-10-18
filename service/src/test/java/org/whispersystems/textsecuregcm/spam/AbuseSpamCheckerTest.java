/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.container.ContainerRequestContext;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;

class AbuseSpamCheckerTest {

  @Test
  void multiRecipientHttpRequestsCarryTrustedSourceAndUniqueAttemptEvidence() {
    final AbuseClient abuseClient = mock(AbuseClient.class);
    final ContainerRequestContext requestContext = mock(ContainerRequestContext.class);
    when(requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME))
        .thenReturn("203.0.113.42");
    when(abuseClient.evaluate(anyString(), anyString(), anyString()))
        .thenReturn(new AbuseClient.Decision(false, ""));

    final AbuseSpamChecker spamChecker = new AbuseSpamChecker(abuseClient);
    spamChecker.checkForMultiRecipientSpamHttp(MessageType.MULTI_RECIPIENT_SEALED_SENDER, requestContext);
    spamChecker.checkForMultiRecipientSpamHttp(MessageType.MULTI_RECIPIENT_SEALED_SENDER, requestContext);

    final ArgumentCaptor<String> subjectIds = ArgumentCaptor.forClass(String.class);
    final ArgumentCaptor<String> evidenceReferences = ArgumentCaptor.forClass(String.class);
    verify(abuseClient, times(2)).evaluate(anyString(), subjectIds.capture(), evidenceReferences.capture());

    assertThat(subjectIds.getAllValues()).containsOnly("multi-recipient:203.0.113.42");
    final List<String> references = evidenceReferences.getAllValues();
    assertThat(references).allMatch(reference -> reference.startsWith("request:"));
    assertThat(references).doesNotHaveDuplicates();
  }
}
