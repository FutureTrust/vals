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

package eu.futuretrust.vals.protocol.detection;

import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.futuretrust.vals.core.DSSValidator;
import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.ers.ERSDSSValidator;
import eu.futuretrust.vals.core.etsi.esi.AdESDSSValidator;
import eu.futuretrust.vals.core.jws.JWSDSSValidator;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.utils.VerifyRequestUtils;

public class ProfileDispatcher {

  public static DSSValidator getValidator(final VerifyRequestType verifyRequest,
      final CertificateVerifier certificateVerifier) throws ProfileNotFoundException {

    Profile mainProfile = VerifyRequestUtils.getMainProfile(verifyRequest);

    switch (mainProfile) {
      case DSS_ADES:
      case DSS_CORE_2:
        return new AdESDSSValidator(certificateVerifier);
      case ERS:
        return new ERSDSSValidator(certificateVerifier);
      case JWS:
        return new JWSDSSValidator(certificateVerifier);
      default:
        return null;
    }
  }
}
