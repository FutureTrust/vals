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

package eu.futuretrust.vals.protocol.response;

import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.PolicyException;
import eu.futuretrust.vals.protocol.exceptions.VerifyRequestException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class VerifyResponseBuilder
{
  private static final Logger LOGGER = LoggerFactory.getLogger(VerifyResponseBuilder.class);

  private Policy defaultPolicy;

  protected VerifyRequestType verifyRequest;

  protected DSSResponseType responseType;

  VerifyResponseBuilder(final VerifyRequestType verifyRequest,
                        final Policy policy,
                        final CertificateVerifier certificateVerifier,
                        final DSSResponseType responseType) throws VerifyRequestException, PolicyException
  {

    if (isInvalid(verifyRequest))
    {
      throw new VerifyRequestException("VerifyRequest is invalid", ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    if (defaultPolicy == null
            || defaultPolicy.getContent() == null
            || defaultPolicy.getContent().length == 0
            || StringUtils.isEmpty(defaultPolicy.getUrl())) {
      throw new PolicyException("Default policy is invalid", ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    final ValidationReport report = null;
  }

  private boolean isInvalid(final VerifyRequestType verifyRequest) {

    if (verifyRequest == null) {
      return true;
    }
    if (verifyRequest.getSignatureObject() != null
            && verifyRequest.getOptionalInputs() != null
            &&verifyRequest.getOptionalInputs().getDocumentWithSignature() != null) {
      return true;
    }
    return false;
  }


}
