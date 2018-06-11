package eu.futuretrust.vals.web.services.response;

import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.PolicyException;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.exceptions.VerifyRequestException;
import eu.futuretrust.vals.protocol.input.Policy;

public interface VerifyResponseBuilderService {

  VerifyResponseType generate(final VerifyRequestType verifyRequest, final Policy defaultPolicy,
      DSSResponseType responseType)
      throws VerifyRequestException, PolicyException, ProfileNotFoundException;
}
