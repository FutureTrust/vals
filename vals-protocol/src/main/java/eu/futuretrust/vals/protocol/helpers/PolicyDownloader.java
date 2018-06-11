package eu.futuretrust.vals.protocol.helpers;

import eu.futuretrust.vals.protocol.input.Policy;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PolicyDownloader {

  private static final Logger LOGGER = LoggerFactory.getLogger(PolicyDownloader.class);

  private PolicyDownloader() {
  }

  public static Optional<Policy> download(List<String> policiesLocation) {
    return policiesLocation.stream().map(PolicyDownloader::extractPolicy).filter(Objects::nonNull)
        .findFirst();
  }

  private static Policy extractPolicy(String policyLocation) {
    Optional<URL> url = getUrl(policyLocation);
    if (!url.isPresent()) {
      return null;
    }

    Optional<byte[]> content = getContent(url.get());
    return content.map(bytes -> new Policy(policyLocation, bytes)).orElse(null);
  }

  private static Optional<URL> getUrl(String policyLocation) {
    try {
      return Optional.of(new URL(policyLocation));
    } catch (MalformedURLException e) {
      LOGGER.error(
          "URL given as policy \"" + policyLocation + "\" is malformed : " + e.getMessage());
      return Optional.empty();
    }
  }

  private static Optional<byte[]> getContent(URL url) {
    InputStream is = null;
    try {
      is = url.openStream();
      byte[] content = IOUtils.toByteArray(is);
      return Optional.ofNullable(content);
    } catch (IOException e) {
      LOGGER.error(
          "Could not read the content from URL \"" + url.getPath() + "\" : " + e.getMessage());
      return Optional.empty();
    } finally {
      if (is != null) {
        try {
          is.close();
        } catch (IOException e) {
          LOGGER.error(
              "Error while closing input stream : " + e.getMessage());
        }
      }
    }
  }

}
