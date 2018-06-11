/*
 * Copyright (c) 2018 European Commission.
 *
 * Licensed under the EUPL, Version 1.2 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/sites/default/files/inline-files/EUPL%20v1_2%20EN(1).txt
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package eu.futuretrust.vals.protocol.utils;

import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.ProfileType;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.collections.CollectionUtils;

public class ProfileUtils {

  /**
   * Retrieves the (first) main profile from a given VerifyRequest
   *
   * @param verifyRequest verify request to be inspected
   * @return profile found in the verify request
   */
  public static Profile getMainProfile(final VerifyRequestType verifyRequest)
      throws ProfileNotFoundException {
    if (CollectionUtils.isEmpty(verifyRequest.getProfile())) {
      throw new ProfileNotFoundException(
          "The Profile child element of a VerifyRequest element shall have at least one profile",
          ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED);
    }
    return getMainProfile(verifyRequest.getProfile());
  }

  /**
   * Retrieves the (first) main profile from a provided list of profiles
   */
  public static Profile getMainProfile(final List<String> profiles)
      throws ProfileNotFoundException {
    return profiles.stream()
        .map(Profile::fromUri)
        .filter(profile -> profile.getType().equals(ProfileType.MAIN))
        .findFirst()
        .orElseThrow(
            () -> new ProfileNotFoundException(
                "The Profile child element of a VerifyRequest element does not contain suitable profile",
                ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED));
  }

  /**
   * Retrieves the list of sub profiles from a given VerifyRequest
   *
   * @param verifyRequest verify request to be inspected
   */
  public static List<Profile> getSubProfiles(final VerifyRequestType verifyRequest) {
    return getSubProfiles(verifyRequest.getProfile());
  }

  /**
   * Retrieves the list of sub profiles from a given list of profiles
   */
  public static List<Profile> getSubProfiles(final List<String> profiles) {
    return profiles.stream()
        .map(Profile::fromUri)
        .filter(profile -> profile.getType().equals(ProfileType.SUB))
        .collect(Collectors.toList());
  }

}
