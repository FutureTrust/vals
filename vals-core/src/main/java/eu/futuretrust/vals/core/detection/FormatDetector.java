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

package eu.futuretrust.vals.core.detection;

import com.sun.deploy.uitoolkit.impl.fx.ui.CertificateDialog;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.signature.exceptions.FormatException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Optional;
import org.apache.tika.Tika;

public final class FormatDetector {

  private static final Tika TIKA = new Tika();

  private FormatDetector() {
  }

  public static SignedObjectFormat detect(File file)
      throws IOException, FormatException {
    String fileType = TIKA.detect(file);
    return getSignedObjectFormat(fileType);
  }

  public static SignedObjectFormat detect(InputStream is)
      throws IOException, FormatException {
    String fileType = TIKA.detect(is);
    return getSignedObjectFormat(fileType);
  }

  public static SignedObjectFormat detect(byte[] bytes) throws FormatException {
    if (isX509Certificate(bytes)) {
      return SignedObjectFormat.X509;
    }
    String fileType = TIKA.detect(bytes);
    return getSignedObjectFormat(fileType);
  }

  private static SignedObjectFormat getSignedObjectFormat(String fileType)
      throws FormatException {
    Optional<SignedObjectFormat> optionalSignatureFormat = SignedObjectFormat.fromString(fileType);
    if (!optionalSignatureFormat.isPresent()) {
      throw new FormatException(
          "The signature format cannot be detected (please check that you are submitting a XML, PDF, CMS document or ASiC container)");
    }
    return optionalSignatureFormat.get();
  }

  private static boolean isX509Certificate(final byte[] bytes)
  {
    try
    {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      factory.generateCertificate(new ByteArrayInputStream(bytes));
    } catch (final Exception e) {
      return false;
    }
    return true;
  }

}
