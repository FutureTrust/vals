package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class AsicVerifyRequestBuilder extends VerifyRequestBuilder {

  private static final Logger LOGGER = LoggerFactory.getLogger(AsicVerifyRequestBuilder.class);

  /**
   * Instantiate by the following factory {@link VerifyRequestBuilderFactory}
   *
   * @param signature signature file to be validated
   */
  AsicVerifyRequestBuilder(byte[] signature) {
    super(signature);
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("New ASiC Verify Request Builder");
    }
  }

  @Override
  public VerifyRequestType generate() {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Generating new ASiC Verify Request");
    }

    setCommonDefaultAttributes();

    Base64DataType base64DataSignature = getBase64Data(SignatureFormat.ASIC.getMimeTypes()[0]);

    setSignatureObject(base64DataSignature);

    LOGGER.info("ASiC Verify Request has been generated");
    return this.getVerifyRequest();
  }

  @Override
  public SignatureFormat getSignatureFormat() {
    return SignatureFormat.ASIC;
  }

  @Override
  public SignedObjectType getSignatureType() throws SignatureException
  {
    return SignedObjectType.DETACHED;
  }

}
