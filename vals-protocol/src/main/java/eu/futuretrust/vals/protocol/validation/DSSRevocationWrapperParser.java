package eu.futuretrust.vals.protocol.validation;

import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;
import java.lang.reflect.Field;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A DSSRevocationWrapperParser is an object which proposes to retrieve RevocationWrapper's
 * attributes
 */
public class DSSRevocationWrapperParser {

  private static final Logger LOGGER = LoggerFactory.getLogger(DSSRevocationWrapperParser.class);

  /**
   * Returns a XmlRevocation from the {@code revocationWrapper} or empty if the field could not be
   * found because of an internal error
   *
   * @param revocationWrapper : an initialized RevocationWrapper.
   */
  public XmlRevocation getXmlRevocationField(RevocationWrapper revocationWrapper)
      throws DSSParserException {
    if (revocationWrapper == null) {
      throw new DSSParserException("RevocationWrapper is null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    Field field;
    try {
      field = RevocationWrapper.class.getDeclaredField("revocation");
      field.setAccessible(true);
      return (XmlRevocation) field.get(revocationWrapper);
    } catch (NoSuchFieldException | IllegalAccessException ignored) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER.error("Unable to use reflection on field certificate");
      }
    }
    throw new DSSParserException("Could not extract XmlRevocation", ResultMajor.RESPONDER_ERROR,
        ResultMinor.GENERAL_ERROR);
  }


  public byte[] getRevocationBase64(RevocationWrapper revocationWrapper)
      throws DSSParserException {
    if (revocationWrapper == null) {
      throw new DSSParserException("RevocationWrapper is null", ResultMajor.RESPONDER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
    XmlRevocation xmlRevocation = getXmlRevocationField(revocationWrapper);
    // TODO: return Base64.encode(xmlRevocation.getBase64Encoded());
    return new byte[0];
  }

}
