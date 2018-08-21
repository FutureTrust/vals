/*
 * Copyright (c) 2018 European Commission.
 *
 * Licensed under the EUPL, Version 1.2 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/sites/default/files/inline-files/EUPL%20v1_2%20EN(1).txt
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package eu.futuretrust.vals.core.enums;

import java.util.Arrays;
import java.util.Optional;

public enum SignedObjectFormat
{
  XML("application/xml"),
  PDF("application/pdf"),
  CMS("application/pkcs7-signature", "application/cms"),
  ASIC("application/zip", "application/vnd.etsi.asic-e+zip", "application/vnd.etsi.asic-s+zip"),
  //Note: Mimetypes starting with "x" are unregistered...
  X509("application/pkix-cert", "application/x-x509-user-cert", "application/x-x509-ca-cert", "application/x-x509-email-cert",
               "application/x-pem-file", "application/pkix", "application/pkix-attr-cert"),
  BYTES("application/octet-stream"),
  TIMESTAMP("application/vnd.etsi.timestamp-token"),
  TSL("application/vnd.etsi.tsl.der", "application/vnd.etsi.tsl+xml"),
  JWT("application/jwt"),
  SAMLv2("application/xml");

  private String[] mimeTypes;

  SignedObjectFormat(String... mimeTypes) {
    this.mimeTypes = mimeTypes;
  }

  public String[] getMimeTypes() {
    return mimeTypes;
  }

  public static Optional<SignedObjectFormat> fromString(final String mimeType)
  {
    return Arrays.stream(SignedObjectFormat.values())
            .filter(signedObject -> Arrays.stream(
                    signedObject.mimeTypes).anyMatch(
                    type -> type.equalsIgnoreCase(mimeType)))
            .findFirst();
  }
}
