package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PadesVerifyRequestBuilder extends VerifyRequestBuilder {

  private static final Logger LOGGER = LoggerFactory.getLogger(PadesVerifyRequestBuilder.class);

  /**
   * Instantiate by the following factory {@link VerifyRequestBuilderFactory}
   *
   * @param signature signature file to be validated
   */
  PadesVerifyRequestBuilder(byte[] signature) {
    super(signature);
    LOGGER.info("New PadES Verify Request Builder");
  }

  @Override
  public VerifyRequestType generate() {
    LOGGER.info("Generating new PadES Verify Request");

    setCommonDefaultAttributes();

    Base64DataType base64DataSignature = getBase64Data(SignatureFormat.PDF.getMimeTypes()[0]);

    // PadES is considered as an enveloped signature
    setDocumentWithSignature(base64DataSignature);

    LOGGER.info("PadES Verify Request has been generated");
    return this.getVerifyRequest();
  }

  @Override
  public SignatureFormat getSignatureFormat() {
    return SignatureFormat.PDF;
  }

  @Override
  public SignedObjectType getSignatureType() {
    return SignedObjectType.ENVELOPED;
  }

}
