package eu.futuretrust.vals.web.services.policy.impl;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.protocol.exceptions.PolicyException;
import eu.futuretrust.vals.protocol.input.Policy;
import eu.futuretrust.vals.web.properties.PolicyProperties;
import eu.futuretrust.vals.web.services.policy.PolicyFetchingService;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

@Service
public class PolicyFetchingServiceImpl implements PolicyFetchingService {

  private static final Logger LOGGER = LoggerFactory.getLogger(PolicyFetchingServiceImpl.class);

  private final PolicyProperties policyProperties;

  @Autowired
  public PolicyFetchingServiceImpl(PolicyProperties policyProperties) {
    this.policyProperties = policyProperties;
  }

  /**
   * Returns the DSS default validation Policy
   *
   * @throws PolicyException whenever an error occurs when loading the DSS default validation
   * policy
   */
  @Override
  public Policy fetch() throws PolicyException {
    if (this.policyProperties == null || this.policyProperties.getFolder() == null || StringUtils
        .isEmpty(this.policyProperties.getName())) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER.error(
            "Could not load the policy file, unable to find the file in resources or the folder is null or the filename is empty");
      }
      throw new PolicyException("Could not load the default policy file",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Fetching policy: {}", this.policyProperties.getName());
    }

    byte[] policyContent = getPolicyContent();
    String hostname = policyProperties.getUrl();
    String url = createUrl(hostname);

    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("{} has been fetched and should be available at: {}", this.policyProperties.getName(),
          url);
    }

    return new Policy(url, policyContent);
  }

  private byte[] getPolicyContent() throws PolicyException {
    InputStream is;
    try {
      is = new ClassPathResource(this.policyProperties.getFolder() + this.policyProperties.getName())
          .getInputStream();
    } catch (IOException e) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER.error("Could not load the policy file: {}", this.policyProperties.getName());
      }
      throw new PolicyException("No default policy found",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    byte[] policyContent;
    try {
      policyContent = IOUtils.toByteArray(is);
    } catch (IOException e) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER.error("Could not load the policy file: {}", this.policyProperties.getName());
      }
      throw new PolicyException("No default policy found",
          ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }
    return policyContent;
  }

  private String createUrl(String hostName) {
    return hostName + "/" + this.policyProperties.getPath() + this.policyProperties.getName();
  }

}

