/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.grpc;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.Message;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;
import org.signal.chat.remoteconfiguration.Badges;
import org.signal.chat.remoteconfiguration.Configuration;
import org.signal.chat.remoteconfiguration.GetBadgesRequest;
import org.signal.chat.remoteconfiguration.GetBadgesResponse;
import org.signal.chat.remoteconfiguration.GetConfigurationRequest;
import org.signal.chat.remoteconfiguration.GetConfigurationResponse;
import org.signal.chat.remoteconfiguration.SimpleRemoteConfigurationGrpc;
import org.signal.chat.remoteconfiguration.TaggedBadges;
import org.signal.chat.remoteconfiguration.TaggedConfiguration;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticationUtil;
import org.whispersystems.textsecuregcm.storage.RemoteConfigsManager;

public class RemoteConfigurationGrpcService extends SimpleRemoteConfigurationGrpc.RemoteConfigurationImplBase {

  private static final GetConfigurationResponse CONFIGURATION_ETAG_MATCHED =
      GetConfigurationResponse.newBuilder().setEtagMatched(true).build();
  private static final GetBadgesResponse BADGES_ETAG_MATCHED =
      GetBadgesResponse.newBuilder().setEtagMatched(true).build();
  private static final Badges EMPTY_BADGES = Badges.getDefaultInstance();
  private static final ByteString EMPTY_BADGES_ETAG = etag(EMPTY_BADGES);

  private final RemoteConfigsManager remoteConfigsManager;

  public RemoteConfigurationGrpcService(final RemoteConfigsManager remoteConfigsManager) {
    this.remoteConfigsManager = remoteConfigsManager;
  }

  @Override
  public GetConfigurationResponse getConfiguration(final GetConfigurationRequest request) {
    final UUID accountIdentifier = AuthenticationUtil.requireAuthenticatedDevice().accountIdentifier();
    final String userAgent = RequestAttributesUtil.getUserAgent().orElse(null);
    final Map<String, String> configForAccount = remoteConfigsManager.getConfigForAccount(accountIdentifier, userAgent);

    final Configuration configuration = Configuration.newBuilder()
        .putAllConfiguration(configForAccount)
        .build();

    final ByteString etagByteString = etag(configuration);
    if (etagByteString.equals(request.getEtag())) {
      return CONFIGURATION_ETAG_MATCHED;
    }
    return GetConfigurationResponse.newBuilder()
        .setTaggedConfiguration(TaggedConfiguration.newBuilder()
            .setEtag(etagByteString)
            .setConfiguration(configuration))
        .build();
  }

  @Override
  public GetBadgesResponse getBadges(final GetBadgesRequest request) {
    if (EMPTY_BADGES_ETAG.equals(request.getEtag())) {
      return BADGES_ETAG_MATCHED;
    }

    final TaggedBadges taggedBadges = TaggedBadges.newBuilder()
        .setBadges(EMPTY_BADGES)
        .setEtag(EMPTY_BADGES_ETAG)
        .build();

    return GetBadgesResponse.newBuilder().setTaggedBadges(taggedBadges).build();
  }

  private static ByteString etag(final Message message) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream(message.getSerializedSize());
    final CodedOutputStream cos = CodedOutputStream.newInstance(baos);
    cos.useDeterministicSerialization();
    try {
      message.writeTo(cos);
      cos.flush();
      return ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(baos.toByteArray()));
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }
}
