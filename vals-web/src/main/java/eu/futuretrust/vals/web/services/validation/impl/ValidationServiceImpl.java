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

package eu.futuretrust.vals.web.services.validation.impl;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.PolicyException;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.exceptions.VerifyRequestException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.protocol.utils.VerifyResponseUtils;
import eu.futuretrust.vals.web.services.policy.PolicyFetchingService;
import eu.futuretrust.vals.web.services.response.VerifyResponseBuilderService;
import eu.futuretrust.vals.web.services.validation.ValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ValidationServiceImpl implements ValidationService {

  private static final Logger LOGGER = LoggerFactory.getLogger(ValidationServiceImpl.class);

  private final PolicyFetchingService policyFetchingService;
  private final VerifyResponseBuilderService verifyResponseBuilderService;

  @Autowired
  public ValidationServiceImpl(PolicyFetchingService policyFetchingService,
      VerifyResponseBuilderService verifyResponseBuilderService) {
    this.policyFetchingService = policyFetchingService;
    this.verifyResponseBuilderService = verifyResponseBuilderService;
  }

  @Override
  public VerifyResponseType validate(final VerifyRequestType verifyRequest,
      final DSSResponseType responseType) throws VerifyRequestException {

    if (null == verifyRequest) {
      throw new VerifyRequestException("VerifyRequest cannot be null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    try {
      Policy policy = policyFetchingService.fetch();
      return verifyResponseBuilderService.generate(verifyRequest, policy, responseType);
    } catch (PolicyException | ProfileNotFoundException | VerifyRequestException e) {
      return VerifyResponseUtils
          .getVerifyResponse(e.getResultMajor(), e.getResultMinor(), e.getMessage(), verifyRequest);
    }
  }

}