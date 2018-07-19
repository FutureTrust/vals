package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.detection.FormatDetector;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory used to instantiate a {@link VerifyRequestBuilder}
 */
public final class VerifyRequestBuilderFactory
{

  private static final Logger LOGGER = LoggerFactory.getLogger(VerifyRequestBuilderFactory.class);

  /**
   * Factory class implied private constructor
   */
  private VerifyRequestBuilderFactory() {}

  /**
   * Create a new instantiate of a {@link VerifyRequestBuilder} object
   *
   * @param signature signature file to be validated
   * @return the {@link VerifyRequestBuilder} to be used for creating a {@link
   * @throws SignatureException when the signature is null
   */
  public static VerifyRequestBuilder newInstance(byte[] signature) throws SignatureException, FormatException
  {
    if (signature == null) {
      throw new SignatureException("Signature content cannot be null");
    }

    SignedObjectFormat signatureFormat = FormatDetector.detect(signature);

    switch (signatureFormat) {
      case XML:
        return new XadesVerifyRequestBuilder(signature);
      case CMS:
        return new CadesVerifyRequestBuilder(signature);
      case PDF:
        return new PadesVerifyRequestBuilder(signature);
      case ASIC:
        return new AsicVerifyRequestBuilder(signature);
      case X509:
        return new X509VerifyRequestBuilder(signature);
      default:
        throw new SignatureException("The signature format cannot be detected");
    }
  }

}
