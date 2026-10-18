/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import io.dropwizard.lifecycle.Managed;

/**
 * Security Phone's explicit cross-boundary abuse decision client.
 *
 * <p>Every implementation must fail closed. An allow decision is accepted only when the boundary service reports both
 * an allow result and a human approval.</p>
 */
public interface AbuseClient extends Managed {

  record Decision(boolean allowed, String reviewId) {
    static Decision denied() {
      return new Decision(false, "");
    }
  }

  Decision evaluate(String signalType, String subjectId, String evidenceReference);

  static AbuseClient denyAll() {
    return new AbuseClient() {
      @Override
      public Decision evaluate(final String signalType, final String subjectId, final String evidenceReference) {
        return Decision.denied();
      }

      @Override
      public void start() {
      }

      @Override
      public void stop() {
      }
    };
  }
}
