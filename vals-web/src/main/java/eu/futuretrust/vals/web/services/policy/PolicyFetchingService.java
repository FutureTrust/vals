package eu.futuretrust.vals.web.services.policy;

import eu.futuretrust.vals.protocol.exceptions.PolicyException;
import eu.futuretrust.vals.protocol.input.Policy;

public interface PolicyFetchingService {

  /**
   * Returns the default validation Policy
   *
   * @throws PolicyException whenever an error occurs when loading the default validation
   * policy
   */
  Policy fetch() throws PolicyException;

}
