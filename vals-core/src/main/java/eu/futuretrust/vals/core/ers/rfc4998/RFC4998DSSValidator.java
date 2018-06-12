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

package eu.futuretrust.vals.core.ers.rfc4998;

import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.futuretrust.vals.core.ers.ERSDSSValidator;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;

public class RFC4998DSSValidator extends ERSDSSValidator
{


  public RFC4998DSSValidator(CertificateVerifier certificateVerifier)
  {
    super(certificateVerifier);
  }

  @Override
  public VerifyResponseType validate(final VerifyRequestType verifyRequestType) {

    return null;

  }

}