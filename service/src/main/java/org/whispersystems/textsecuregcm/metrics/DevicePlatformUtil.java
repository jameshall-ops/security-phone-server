/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.metrics;

import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

public class DevicePlatformUtil {

  private DevicePlatformUtil() {
  }

  /**
   * Returns the most likely client platform for a device.
   *
   * @param device the device for which to find a client platform
   *
   * @return the most likely client platform for the given device or empty if no likely platform could be determined
   */
  public static Optional<ClientPlatform> getDevicePlatform(final Device device) {
    final Optional<ClientPlatform> clientPlatform;

    if (StringUtils.isNotBlank(device.getGcmId())) {
      clientPlatform = Optional.of(ClientPlatform.ANDROID);
    } else if (StringUtils.isNotBlank(device.getApnId())) {
      clientPlatform = Optional.of(ClientPlatform.IOS);
    } else {
      clientPlatform = Optional.empty();
    }

    return clientPlatform;
  }
}
