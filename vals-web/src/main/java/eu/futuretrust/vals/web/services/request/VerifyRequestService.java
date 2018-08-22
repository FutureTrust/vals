package eu.futuretrust.vals.web.services.request;

import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.protocol.request.VerifyRequestBuilder;
import eu.futuretrust.vals.protocol.request.VerifyRequestBuilderFactory;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VerifyRequestService
{

  public VerifyRequestType generate(byte[] bytesSignature, List<InputDocument> inputDocuments)
          throws SignatureException, FormatException
  {
    VerifyRequestBuilder verifyRequestBuilder = VerifyRequestBuilderFactory
            .newInstance(bytesSignature);

    if (CollectionUtils.isNotEmpty(inputDocuments)) {
      verifyRequestBuilder.setDocuments(inputDocuments);
    }

    return verifyRequestBuilder.generate();
  }
}
