package eu.futuretrust.vals.protocol.extractors;

import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.helpers.PolicyDownloader;
import eu.futuretrust.vals.protocol.input.Policy;
import java.util.List;
import java.util.Optional;
import org.apache.commons.collections.CollectionUtils;

public class PolicyExtractor {

  private VerifyRequestType verifyRequest;

  public PolicyExtractor(VerifyRequestType verifyRequest) {
    this.verifyRequest = verifyRequest;
  }

  public Optional<Policy> extract() {
    if (containsPolicy(verifyRequest)) {
      List<String> policies = verifyRequest.getOptionalInputs().getServicePolicy();
      return PolicyDownloader.download(policies);
    }

    return Optional.empty();
  }

  private static boolean containsPolicy(VerifyRequestType verifyRequestType) {
    return verifyRequestType.getOptionalInputs() != null
        && verifyRequestType.getOptionalInputs().getServicePolicy() != null
        && CollectionUtils.isNotEmpty(
        verifyRequestType.getOptionalInputs().getServicePolicy());
  }

}
