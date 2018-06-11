package eu.futuretrust.vals.web.services.response;


import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;

public interface VerifyResponseGenerationService {

  /**
   * Returns a VerifyResponseType in answer to a VerifyRequest @verifyRequest
   */
  VerifyResponseType generate(VerifyRequestType verifyRequest, DSSResponseType responseType);
}
