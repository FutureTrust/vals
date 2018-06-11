package eu.futuretrust.vals.web.services.jaxb;

import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import java.io.InputStream;

public interface JaxbService {

  <T> T unmarshal(InputStream is, Class<T> clazz);

  <T> T unmarshal(byte[] bytes, Class<T> clazz);

  <T> T unmarshal(String str, Class<T> clazz);

  byte[] marshalVerifyRequest(VerifyRequestType verifyRequestType);

  byte[] marshalVerifyResponse(VerifyResponseType verifyResponse);
}
