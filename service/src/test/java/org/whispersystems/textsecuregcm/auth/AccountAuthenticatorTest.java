/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.auth.basic.BasicCredentials;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.cartesian.CartesianTest;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.tests.util.AccountsHelper;
import org.whispersystems.textsecuregcm.util.Pair;
import org.whispersystems.textsecuregcm.util.TestClock;

class AccountAuthenticatorTest {

  private AccountsManager          accountsManager;
  private AccountAuthenticator accountAuthenticator;
  private TestClock                clock;

  @BeforeEach
  void setup() {
    accountsManager = mock(AccountsManager.class);
    clock = TestClock.now();
    accountAuthenticator = new AccountAuthenticator(accountsManager, clock);

    AccountsHelper.setupMockUpdate(accountsManager);
  }

  private static Device generateTestDevice(final long lastSeen) {
    final Device device = new Device();
    device.setId(Device.PRIMARY_ID);
    device.setLastSeen(lastSeen);

    return device;
  }

  @Test
  void testLastSeenChangesAtMostOncePerSevenDays() {
    final UUID accountIdentifier = new UUID(0, 0);
    final long weekStart = Instant.parse("2026-10-15T00:00:00Z").toEpochMilli();
    final Device device = generateTestDevice(weekStart);
    final Account account = AccountsHelper.generateTestAccount(
        "+14088675312", accountIdentifier, UUID.randomUUID(), List.of(device), null);
    AccountsHelper.setupMockGet(accountsManager, account);

    clock.pin(Instant.ofEpochMilli(weekStart).plus(Duration.ofDays(1)));
    accountAuthenticator.updateLastSeen(account, device);

    clock.pin(Instant.ofEpochMilli(weekStart).plus(Duration.ofDays(7)).minusMillis(1));
    accountAuthenticator.updateLastSeen(account, device);

    clock.pin(Instant.ofEpochMilli(weekStart).plus(Duration.ofDays(7)));
    accountAuthenticator.updateLastSeen(account, device);

    verify(accountsManager, times(1)).updateDeviceLastSeen(
        eq(accountIdentifier), eq(device), eq(weekStart + Duration.ofDays(7).toMillis()));
    assertThat(device.getLastSeen()).isEqualTo(weekStart + Duration.ofDays(7).toMillis());
  }

  @Test
  void testLastSeenWeeklyOffsetIsStableAndAccountSpecific() {
    clock.pin(Instant.parse("2026-10-18T12:00:00Z"));
    final UUID firstAccount = UUID.fromString("00000000-0000-0000-0000-000000000001");
    final UUID secondAccount = UUID.fromString("00000000-0000-0000-0000-000000000002");

    final long firstBucket = AccountAuthenticator.weeklyLastSeenBucketStartMillis(firstAccount, clock);
    final long secondBucket = AccountAuthenticator.weeklyLastSeenBucketStartMillis(secondAccount, clock);

    assertThat(secondBucket - firstBucket).isEqualTo(1_000L);

    clock.pin(clock.instant().plus(Duration.ofDays(7)));
    assertThat(AccountAuthenticator.weeklyLastSeenBucketStartMillis(firstAccount, clock) - firstBucket)
        .isEqualTo(Duration.ofDays(7).toMillis());
  }

  @Test
  void testAuthenticate() {
    final UUID uuid = UUID.randomUUID();
    final byte deviceId = 1;
    final String password = "12345";

    final Account account = mock(Account.class);
    final Device device = mock(Device.class);
    final SaltedTokenHash credentials = mock(SaltedTokenHash.class);

    clock.unpin();
    when(accountsManager.getByAccountIdentifier(uuid)).thenReturn(Optional.of(account));
    when(account.getAccountIdentifier()).thenReturn(uuid);
    when(account.getDevice(deviceId)).thenReturn(Optional.of(device));
    when(account.getPrimaryDevice()).thenReturn(device);
    when(device.getId()).thenReturn(deviceId);
    when(device.getAuthTokenHash()).thenReturn(credentials);
    when(credentials.verify(password)).thenReturn(true);

    final Optional<AuthenticatedDevice> maybeAuthenticatedAccount =
        accountAuthenticator.authenticate(new BasicCredentials(uuid.toString(), password));

    assertThat(maybeAuthenticatedAccount).isPresent();
    assertThat(maybeAuthenticatedAccount.orElseThrow().accountIdentifier()).isEqualTo(uuid);
    assertThat(maybeAuthenticatedAccount.orElseThrow().deviceId()).isEqualTo(device.getId());
  }

  @Test
  void testAuthenticateNonDefaultDevice() {
    final UUID uuid = UUID.randomUUID();
    final byte deviceId = 2;
    final String password = "12345";

    final Account account = mock(Account.class);
    final Device device = mock(Device.class);
    final SaltedTokenHash credentials = mock(SaltedTokenHash.class);

    clock.unpin();
    when(accountsManager.getByAccountIdentifier(uuid)).thenReturn(Optional.of(account));
    when(account.getAccountIdentifier()).thenReturn(uuid);
    when(account.getDevice(deviceId)).thenReturn(Optional.of(device));
    when(account.getPrimaryDevice()).thenReturn(device);
    when(device.getId()).thenReturn(deviceId);
    when(device.getAuthTokenHash()).thenReturn(credentials);
    when(credentials.verify(password)).thenReturn(true);

    final Optional<AuthenticatedDevice> maybeAuthenticatedAccount =
        accountAuthenticator.authenticate(new BasicCredentials(uuid + "." + deviceId, password));

    assertThat(maybeAuthenticatedAccount).isPresent();
    assertThat(maybeAuthenticatedAccount.orElseThrow().accountIdentifier()).isEqualTo(uuid);
    assertThat(maybeAuthenticatedAccount.orElseThrow().deviceId()).isEqualTo(device.getId());
  }

  @CartesianTest
  void testAuthenticateEnabled(
      @CartesianTest.Values(booleans = {true, false}) final boolean authenticatedDeviceIsPrimary) {
    final UUID uuid = UUID.randomUUID();
    final byte deviceId = (byte) (authenticatedDeviceIsPrimary ? 1 : 2);
    final String password = "12345";

    final Account account = mock(Account.class);
    final Device authenticatedDevice = mock(Device.class);
    final SaltedTokenHash credentials = mock(SaltedTokenHash.class);

    clock.unpin();
    when(accountsManager.getByAccountIdentifier(uuid)).thenReturn(Optional.of(account));
    when(account.getAccountIdentifier()).thenReturn(uuid);
    when(account.getDevice(deviceId)).thenReturn(Optional.of(authenticatedDevice));
    when(account.getPrimaryDevice()).thenReturn(authenticatedDevice);
    when(authenticatedDevice.getId()).thenReturn(deviceId);
    when(authenticatedDevice.getAuthTokenHash()).thenReturn(credentials);
    when(credentials.verify(password)).thenReturn(true);

    final String identifier;
    if (authenticatedDeviceIsPrimary) {
      identifier = uuid.toString();
    } else {
      identifier = uuid.toString() + AccountAuthenticator.DEVICE_ID_SEPARATOR + deviceId;
    }
    final Optional<AuthenticatedDevice> maybeAuthenticatedAccount =
        accountAuthenticator.authenticate(new BasicCredentials(identifier, password));

    assertThat(maybeAuthenticatedAccount).isPresent();
    assertThat(maybeAuthenticatedAccount.orElseThrow().accountIdentifier()).isEqualTo(uuid);
    assertThat(maybeAuthenticatedAccount.orElseThrow().deviceId()).isEqualTo(authenticatedDevice.getId());
  }

  @Test
  void testAuthenticateAccountNotFound() {
    assertThat(accountAuthenticator.authenticate(new BasicCredentials(UUID.randomUUID().toString(), "password")))
        .isEmpty();
  }

  @Test
  void testAuthenticateDeviceNotFound() {
    final UUID uuid = UUID.randomUUID();
    final byte deviceId = 1;
    final String password = "12345";

    final Account account = mock(Account.class);
    final Device device = mock(Device.class);
    final SaltedTokenHash credentials = mock(SaltedTokenHash.class);

    clock.unpin();
    when(accountsManager.getByAccountIdentifier(uuid)).thenReturn(Optional.of(account));
    when(account.getAccountIdentifier()).thenReturn(uuid);
    when(account.getDevice(deviceId)).thenReturn(Optional.of(device));
    when(account.getPrimaryDevice()).thenReturn(device);
    when(device.getId()).thenReturn(deviceId);
    when(device.getAuthTokenHash()).thenReturn(credentials);
    when(credentials.verify(password)).thenReturn(true);

    final Optional<AuthenticatedDevice> maybeAuthenticatedAccount =
        accountAuthenticator.authenticate(new BasicCredentials(uuid + "." + (deviceId + 1), password));

    assertThat(maybeAuthenticatedAccount).isEmpty();
    verify(account).getDevice((byte) (deviceId + 1));
  }

  @Test
  void testAuthenticateIncorrectPassword() {
    final UUID uuid = UUID.randomUUID();
    final byte deviceId = 1;
    final String password = "12345";

    final Account account = mock(Account.class);
    final Device device = mock(Device.class);
    final SaltedTokenHash credentials = mock(SaltedTokenHash.class);

    clock.unpin();
    when(accountsManager.getByAccountIdentifier(uuid)).thenReturn(Optional.of(account));
    when(account.getAccountIdentifier()).thenReturn(uuid);
    when(account.getDevice(deviceId)).thenReturn(Optional.of(device));
    when(account.getPrimaryDevice()).thenReturn(device);
    when(device.getId()).thenReturn(deviceId);
    when(device.getAuthTokenHash()).thenReturn(credentials);
    when(credentials.verify(password)).thenReturn(true);

    final String incorrectPassword = password + "incorrect";

    final Optional<AuthenticatedDevice> maybeAuthenticatedAccount =
        accountAuthenticator.authenticate(new BasicCredentials(uuid.toString(), incorrectPassword));

    assertThat(maybeAuthenticatedAccount).isEmpty();
    verify(credentials).verify(incorrectPassword);
  }

  @ParameterizedTest
  @MethodSource
  void testAuthenticateMalformedCredentials(final String username) {
    final Optional<AuthenticatedDevice> maybeAuthenticatedAccount = assertDoesNotThrow(
        () -> accountAuthenticator.authenticate(new BasicCredentials(username, "password")));

    assertThat(maybeAuthenticatedAccount).isEmpty();
    verify(accountsManager, never()).getByAccountIdentifier(any(UUID.class));
  }

  private static Stream<String> testAuthenticateMalformedCredentials() {
    return Stream.of(
        "",
        ".4",
        "This is definitely not a valid UUID",
        UUID.randomUUID() + ".");
  }

  @ParameterizedTest
  @MethodSource
  void testGetIdentifierAndDeviceId(final String username, final String expectedIdentifier,
      final byte expectedDeviceId) {
    final Pair<String, Byte> identifierAndDeviceId = AccountAuthenticator.getIdentifierAndDeviceId(username);

    assertEquals(expectedIdentifier, identifierAndDeviceId.first());
    assertEquals(expectedDeviceId, identifierAndDeviceId.second());
  }

  private static Stream<Arguments> testGetIdentifierAndDeviceId() {
    return Stream.of(
        Arguments.of("", "", Device.PRIMARY_ID),
        Arguments.of("test", "test", Device.PRIMARY_ID),
        Arguments.of("test.7", "test", (byte) 7));
  }

  @ParameterizedTest
  @ValueSource(strings = {
      ".",
      ".....",
      "test.7.8",
      "test."
  })
  void testGetIdentifierAndDeviceIdMalformed(final String malformedUsername) {
    assertThrows(IllegalArgumentException.class,
        () -> AccountAuthenticator.getIdentifierAndDeviceId(malformedUsername));
  }
}
