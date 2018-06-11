package eu.futuretrust.vals.protocol.validation;

import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import java.lang.reflect.Field;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A DSSCertificateWrapperParser is an object which proposes to retrieve CertificateWrapper's
 * attributes
 */
public class DSSCertificateWrapperParser {

  private static final Logger LOGGER = LoggerFactory.getLogger(DSSCertificateWrapperParser.class);


  /**
   * Returns a base64 encoded byte array from the {@code certificateWrapper} or empty if the field
   * could not be found because of an internal error
   *
   * @param certificateWrapper : an initialized RevocationWrapper.
   */
  public byte[] getCertificateBase64(CertificateWrapper certificateWrapper)
      throws DSSParserException {
    if (certificateWrapper == null) {
      throw new DSSParserException("CertificateWrapper is null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    XmlCertificate xmlCertificate = getXmlCertificateField(certificateWrapper);
    return Base64.encode(xmlCertificate.getBase64Encoded());
  }

  /**
   * Returns a XmlCertificate from the {@code certificateWrapper} or empty if the field could not be
   * found because of an internal error
   *
   * @param certificateWrapper : an initialized RevocationWrapper.
   */
  public XmlCertificate getXmlCertificateField(CertificateWrapper certificateWrapper)
      throws DSSParserException {
    if (certificateWrapper == null) {
      throw new DSSParserException("CertificateWrapper is null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    Field field;
    try {
      field = CertificateWrapper.class.getDeclaredField("certificate");
      field.setAccessible(true);
      return (XmlCertificate) field.get(certificateWrapper);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER.error("Unable to use reflection on field certificate");
      }
    }
    throw new DSSParserException("Could not extract XmlCertificate", ResultMajor.RESPONDER_ERROR,
        ResultMinor.GENERAL_ERROR);
  }

}
