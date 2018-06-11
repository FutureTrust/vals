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

package eu.futuretrust.vals.core.enums;

import java.util.Arrays;

public enum Profile {

  DSS_CORE_2("http://uri.etsi.org/19442/v1.1.1/validationprofile#", ProfileType.MAIN),
  ERS("urn:oasis:names:tc:dss:1.0:profiles:EvidenceRecord", ProfileType.MAIN),
  JWS("urn:oasis:names:tc:dss-x:2.0:profiles:JWS", ProfileType.MAIN),
  DSS_ADES("urn:oasis:names:tc:dss:1.0:profiles:AdES:schema#", ProfileType.MAIN),
  DSS_MULTI("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#", ProfileType.SUB),
  ASYNCHRONOUS("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:1.0", ProfileType.SUB);

  private final String uri;
  private final ProfileType type;

  Profile(final String uri, final ProfileType type) {
    this.uri = uri;
    this.type = type;
  }

  public String getUri() {
    return this.uri;
  }

  public ProfileType getType() {
    return this.type;
  }

  public static Profile fromUri(final String uri) {
    return Arrays.stream(Profile.values())
        .filter(p -> p.getUri().equalsIgnoreCase(uri))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unsupported profile URI: " + uri));
  }
}
