package org.whispersystems.textsecuregcm.util;

import com.google.common.annotations.VisibleForTesting;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import javax.annotation.Nullable;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredentialResponse;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCommitment;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequest;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.whispersystems.textsecuregcm.entities.CreateProfileRequest;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.storage.VersionedProfileV1;

public class ProfileHelper {
  public static int MAX_PROFILE_AVATAR_SIZE_BYTES = 10 * 1024 * 1024;
  @VisibleForTesting
  public static final Duration PROFILE_KEY_CREDENTIAL_EXPIRATION = Duration.ofDays(7);

  public static String generateAvatarObjectName() {
    final byte[] object = new byte[16];
    new SecureRandom().nextBytes(object);

    return "profiles/" + Base64.getUrlEncoder().encodeToString(object);
  }

  public static boolean isSelfProfileRequest(@Nullable final UUID requesterUuid, final ServiceIdentifier targetIdentifier) {
    return targetIdentifier.uuid().equals(requesterUuid);
  }

  public static ExpiringProfileKeyCredentialResponse getExpiringProfileKeyCredential(
      final ProfileKeyCredentialRequest request,
      final ProfileKeyCommitment commitment,
      final ServiceId.Aci accountIdentifier,
      final ServerZkProfileOperations zkProfileOperations) throws InvalidInputException, VerificationFailedException {

    final Instant expiration = Instant.now().plus(PROFILE_KEY_CREDENTIAL_EXPIRATION).truncatedTo(ChronoUnit.DAYS);

    return zkProfileOperations.issueExpiringProfileKeyCredential(request, accountIdentifier, commitment, expiration);
  }

  @Nullable
  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  public static String getAvatar(final CreateProfileRequest.AvatarChange avatarChange, final Optional<String> currentAvatar) {
    return switch (avatarChange) {
      case UNCHANGED -> currentAvatar.orElse(null);
      case CLEAR -> null;
      case UPDATE -> ProfileHelper.generateAvatarObjectName();
    };
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  public static Optional<String> getCurrentAvatar(Optional<VersionedProfileV1> maybeV1Profile) {
    return maybeV1Profile.map(VersionedProfileV1::avatar).filter(avatar -> avatar.startsWith("profiles/"));
  }
}
