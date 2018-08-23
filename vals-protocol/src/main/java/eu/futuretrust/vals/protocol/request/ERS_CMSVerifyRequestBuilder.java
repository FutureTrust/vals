package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;

public class ERS_CMSVerifyRequestBuilder extends VerifyRequestBuilder {

    ERS_CMSVerifyRequestBuilder(byte[] certificate) {
      super(certificate);
    }

    @Override
    public VerifyRequestType generate() throws SignatureException
    {
      setRequestID();
      getVerifyRequest().getProfile().add(Profile.ERS.getUri());
      Base64DataType base64DataSignature = getBase64Data(SignedObjectFormat.ERS_CMS.getMimeTypes()[0]);
      setSignatureObject(base64DataSignature);
      return getVerifyRequest();
    }

    @Override
    public SignatureFormat getSignatureFormat()
    {
      return null;
    }

    @Override
    public SignedObjectType getSignatureType() throws SignatureException
    {
      return null;
    }
}

