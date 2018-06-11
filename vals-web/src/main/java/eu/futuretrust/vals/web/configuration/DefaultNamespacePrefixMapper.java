package eu.futuretrust.vals.web.configuration;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultNamespacePrefixMapper extends NamespacePrefixMapper {

  private static final Logger LOGGER = LoggerFactory.getLogger(DefaultNamespacePrefixMapper.class);

  private Map<String, String> namespaceMap = new HashMap<>();

  public DefaultNamespacePrefixMapper() {
    namespaceMap.put("http://www.w3.org/2000/09/xmldsig#", "ds");
    namespaceMap.put("http://www.w3.org/2001/04/xmlenc#", "xenc");
    namespaceMap.put("http://www.w3.org/2001/XMLSchema", "xs");

    namespaceMap.put("urn:oasis:names:tc:dss:2.0:core:schema", "dss");
    namespaceMap.put("urn:oasis:names:tc:SAML:1.0:assertion", "saml");
    namespaceMap.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml2");
    namespaceMap.put("urn:oasis:names:tc:dss:1.0:profiles:verificationreport:schema#", "vr");

    namespaceMap.put("http://uri.etsi.org/19442/v1.1.1#", "etsival");
    namespaceMap.put("http://uri.etsi.org/191022/v1.1.1#", "etsivr");
    namespaceMap.put("http://uri.etsi.org/02231/v2#", "tsl");
    namespaceMap.put("http://uri.etsi.org/01903/v1.3.2#", "xades");

    namespaceMap.put("http://futuretrust.eu/vals/v1.0.0#", "vals");

    if (LOGGER.isInfoEnabled()) {
      String namespacesAsString = "{" + namespaceMap.entrySet().stream()
          .map(entry -> entry.getValue() + "=" + entry.getKey())
          .collect(Collectors.joining(", ")) + "}";
      LOGGER.info("Namespaces: {}", namespacesAsString);
    }
  }

  @Override
  public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
    return namespaceMap.getOrDefault(namespaceUri, suggestion);
  }
}
