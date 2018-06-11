package eu.futuretrust.vals.web.services.report;

import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectType;
import eu.futuretrust.vals.protocol.enums.ValidationObjectTypeId;
import eu.futuretrust.vals.protocol.exceptions.ValidationObjectException;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.output.Certificate;
import eu.futuretrust.vals.protocol.output.Crl;
import eu.futuretrust.vals.protocol.output.Ocsp;
import eu.futuretrust.vals.protocol.output.Timestamp;
import java.util.List;
import java.util.Optional;

public interface ValidationObjectsBuilderService {

  Optional<ValidationObjectType> findByBase64(byte[] base64,
      ValidationObjectListType validationObjectListType);

  /**
   * Find the Validation Object corresponding to the {@code base64} parameter in Validation Objects
   * of type {@link ValidationObjectTypeId} {@code voType}, if it exists
   *
   * @param base64 Base64 value of the Validation Object
   * @param voType type of the Validation Objects to be filtered
   * @return the Validation Objects corresponding to the {@code base64} parameter, or {@code
   * Optional.empty()}
   */
  Optional<ValidationObjectType> findByBase64(byte[] base64,
      ValidationObjectTypeId voType,
      ValidationObjectListType validationObjectListType);

  ValidationObjectListType build(SignedObject signature,
      List<byte[]> signersDocument,
      List<Certificate> certificateVOs,
      List<Timestamp> listPOE,
      List<Ocsp> ocspVOs,
      List<Crl> crlVOs) throws ValidationObjectException;

  /**
   * Find the Validation Object corresponding to the {@code uri} parameter, if it exists
   *
   * @param uri URI of the Validation Object
   * @return the Validation Objects corresponding to the {@code uri} parameter, or {@code
   * Optional.empty()}
   */
  Optional<ValidationObjectType> findByUri(String uri,
      ValidationObjectListType validationObjectListType);

  /**
   * Find the Validation Object corresponding to the {@code object} parameter, if it exists
   *
   * @param object object to find as a "direct" object
   * @return the Validation Objects corresponding to the {@code object} parameter, or {@code
   * Optional.empty()}
   */
  Optional<ValidationObjectType> findByDirect(Object object,
      ValidationObjectListType validationObjectListType);


}
