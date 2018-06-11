package eu.futuretrust.vals.protocol.helpers;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import org.apache.commons.io.IOUtils;

public final class ResourcesUtils {

  private ResourcesUtils() {
  }

  public static InputStream loadInputStream(String file) {
    return ResourcesUtils.class.getClassLoader().getResourceAsStream(file);
  }

  public static byte[] loadBytes(String file) throws IOException {
    return IOUtils.toByteArray(loadInputStream(file));
  }

  public static URI loadURI(String path) throws URISyntaxException {
    return ResourcesUtils.class.getResource(path).toURI();
  }

}
