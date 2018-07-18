package eu.futuretrust.vals.protocol.enums;

import java.util.Arrays;
import java.util.Optional;

public enum SignatureFormat
{
  XML("application/xml"),
  PDF("application/pdf"),
  CMS("application/pkcs7-signature"),
  ASIC("application/zip", "application/vnd.etsi.asic-e+zip", "application/vnd.etsi.asic-s+zip");

  // the first mime type is considered as the default one, other are considered as alternative allowed types
  private String[] mimeTypes;

  SignatureFormat(String... mimeTypes) {
    this.mimeTypes = mimeTypes;
  }

  public String[] getMimeTypes() {
    return mimeTypes;
  }

  public static Optional<SignatureFormat> fromString(String type) {
    return Arrays.stream(SignatureFormat.values())
            .filter(sigType ->
                    Arrays.stream(sigType.mimeTypes).anyMatch(mimeType -> mimeType.equalsIgnoreCase(type)))
            .findFirst();
  }
}
