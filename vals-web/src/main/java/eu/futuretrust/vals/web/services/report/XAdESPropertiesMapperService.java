package eu.futuretrust.vals.web.services.report;


import eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ValidationObjectListType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.UnsignedPropertiesType;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.SignedPropertiesType;
import eu.futuretrust.vals.protocol.exceptions.DSSParserException;

public interface XAdESPropertiesMapperService
{

  UnsignedPropertiesType mapUnsignedProperties(
      eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.UnsignedPropertiesType unsignedPropertiesTypeXADES,
      ValidationObjectListType validationObjectListType) throws DSSParserException;

  SignedPropertiesType mapSignedProperties(
      eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.SignedPropertiesType signedPropertiesTypeXADES,
      ValidationObjectListType validationObjectListType) throws DSSParserException;
}
