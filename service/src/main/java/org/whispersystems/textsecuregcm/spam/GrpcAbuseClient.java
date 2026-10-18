/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import com.securityphone.contracts.v1.AbuseBoundaryServiceGrpc;
import com.securityphone.contracts.v1.EvaluateAbuseRequest;
import com.securityphone.contracts.v1.EvaluateAbuseResponse;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class GrpcAbuseClient implements AbuseClient {

  private static final Logger log = LoggerFactory.getLogger(GrpcAbuseClient.class);

  private final ManagedChannel channel;
  private final AbuseBoundaryServiceGrpc.AbuseBoundaryServiceBlockingStub stub;
  private final Duration timeout;

  public GrpcAbuseClient(final String target, final Duration timeout) {
    this(ManagedChannelBuilder.forTarget(target).useTransportSecurity().build(), timeout);
  }

  GrpcAbuseClient(final ManagedChannel channel, final Duration timeout) {
    this.channel = channel;
    this.stub = AbuseBoundaryServiceGrpc.newBlockingStub(channel);
    this.timeout = timeout;
  }

  @Override
  public Decision evaluate(final String signalType, final String subjectId, final String evidenceReference) {
    try {
      final EvaluateAbuseResponse response = stub.withDeadlineAfter(timeout.toMillis(), TimeUnit.MILLISECONDS)
          .evaluateAbuse(EvaluateAbuseRequest.newBuilder()
              .setSignalType(signalType)
              .setSubjectId(subjectId)
              .setEvidenceReference(evidenceReference)
              .build());

      return response.getAllowed() && response.getHumanApproved()
          ? new Decision(true, response.getReviewId())
          : Decision.denied();
    } catch (final StatusRuntimeException e) {
      log.warn("Abuse boundary unavailable; denying request", e);
      return Decision.denied();
    }
  }

  @Override
  public void start() {
  }

  @Override
  public void stop() throws InterruptedException {
    channel.shutdown();
    if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
      channel.shutdownNow();
    }
  }
}
