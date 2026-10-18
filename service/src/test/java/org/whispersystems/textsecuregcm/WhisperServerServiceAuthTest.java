/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.protobuf.Empty;
import io.grpc.BindableService;
import io.grpc.ServerServiceDefinition;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.signal.chat.require.Auth;
import org.signal.chat.rpc.SimpleAnonymousServiceGrpc;
import org.signal.chat.rpc.SimpleAuthServiceGrpc;

class WhisperServerServiceAuthTest {

  private static final class AuthService extends SimpleAuthServiceGrpc.AuthServiceImplBase {
    @Override
    public Empty authenticatedMethod(final Empty request) {
      return Empty.getDefaultInstance();
    }
  }

  private static final class AnonymousService extends SimpleAnonymousServiceGrpc.AnonymousServiceImplBase {
    @Override
    public Empty anonymousMethod(final Empty request) {
      return Empty.getDefaultInstance();
    }
  }

  @Test
  void acceptsServiceRegisteredWithItsDeclaredAuthenticationMode() throws Exception {
    assertDoesNotThrow(() -> verify(List.of(new AuthService().bindService()), Auth.AUTH_ONLY_AUTHENTICATED));
    assertDoesNotThrow(() -> verify(List.of(new AnonymousService().bindService()), Auth.AUTH_ONLY_ANONYMOUS));
  }

  @Test
  void rejectsServiceRegisteredWithTheWrongAuthenticationMode() throws Exception {
    final InvocationTargetException exception = assertThrows(InvocationTargetException.class,
        () -> verify(List.of(new AuthService().bindService()), Auth.AUTH_ONLY_ANONYMOUS));

    assertInstanceOf(IllegalStateException.class, exception.getCause());
  }

  private static void verify(final List<ServerServiceDefinition> services, final Auth expectedAuth) throws Exception {
    final Method method = WhisperServerService.class.getDeclaredMethod("verifyServiceAuth", List.class, Auth.class);
    method.setAccessible(true);
    method.invoke(null, services, expectedAuth);
  }
}
