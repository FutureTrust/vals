package eu.futuretrust.vals.web.services.response.impl;

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
import eu.futuretrust.vals.web.services.response.VerifyResponseGenerationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class VerifyResponseGenerationServiceImpl implements VerifyResponseGenerationService {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(VerifyResponseGenerationServiceImpl.class);

  private final PolicyFetchingService policyFetchingService;
  private final VerifyResponseBuilderService verifyResponseBuilderService;

  @Autowired
  public VerifyResponseGenerationServiceImpl(PolicyFetchingService policyFetchingService,
      VerifyResponseBuilderService verifyResponseBuilderService) {
    this.policyFetchingService = policyFetchingService;
    this.verifyResponseBuilderService = verifyResponseBuilderService;
  }

  @Override
  public VerifyResponseType generate(VerifyRequestType verifyRequestType, DSSResponseType responseType) {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Verify Response generation service has been called");
    }
    Policy dssPolicy;
    try {
      dssPolicy = policyFetchingService.fetch();
      return verifyResponseBuilderService.generate(verifyRequestType, dssPolicy, responseType);
    } catch (VerifyRequestException | ProfileNotFoundException | PolicyException e) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER
            .error("Error occurred before attempting to validate the signature {}", e.getMessage());
      }
      return VerifyResponseUtils
          .getVerifyResponse(e.getResultMajor(), e.getResultMinor(), e.getMessage(),
              verifyRequestType);
    }
  }

}
