package eu.futuretrust.vals.web.services.jaxb.impl;

import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.ObjectFactory;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequest;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponse;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.web.services.jaxb.JaxbService;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.stereotype.Service;

@Service
public class JaxbServiceImpl implements JaxbService {

  private static final Logger LOGGER = LoggerFactory.getLogger(JaxbServiceImpl.class);

  private final Jaxb2Marshaller jaxb2Marshaller;

  @Autowired
  public JaxbServiceImpl(Jaxb2Marshaller jaxb2Marshaller) {
    this.jaxb2Marshaller = jaxb2Marshaller;
  }

  @Override
  public <T> T unmarshal(InputStream is, Class<T> clazz) {
    LOGGER.info("Unmarshalling object of class: " + clazz.getName());
    return clazz.cast(jaxb2Marshaller.unmarshal(new StreamSource(is)));
  }

  @Override
  public <T> T unmarshal(byte[] bytes, Class<T> clazz) {
    return unmarshal(new ByteArrayInputStream(bytes), clazz);
  }

  @Override
  public <T> T unmarshal(String str, Class<T> clazz) {
    return unmarshal(str.getBytes(), clazz);
  }

  @Override
  public byte[] marshalVerifyRequest(VerifyRequestType verifyRequest) {
    LOGGER.info("Marshalling verify request: " + verifyRequest.getRequestID(), verifyRequest);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ObjectFactory factory = new ObjectFactory();
    VerifyRequest jaxbElement = factory.createVerifyRequest(verifyRequest);
    jaxb2Marshaller.marshal(jaxbElement, new StreamResult(out));
    return out.toByteArray();
  }

  @Override
  public byte[] marshalVerifyResponse(VerifyResponseType verifyResponse) {
    LOGGER.info("Marshalling verify response: " + verifyResponse.getRequestID(), verifyResponse);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ObjectFactory factory = new ObjectFactory();
    VerifyResponse jaxbElement = factory.createVerifyResponse(verifyResponse);

    jaxb2Marshaller.marshal(jaxbElement, new StreamResult(out));
    return out.toByteArray();
  }

}
