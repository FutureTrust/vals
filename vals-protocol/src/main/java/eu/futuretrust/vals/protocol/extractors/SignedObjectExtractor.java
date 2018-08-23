/*
 * Copyright (c) 2018 European Commission.
 *
 * Licensed under the EUPL, Version 1.2 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/sites/default/files/inline-files/EUPL%20v1_2%20EN(1).txt
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package eu.futuretrust.vals.protocol.extractors;

import eu.futuretrust.vals.core.detection.FormatDetector;
import eu.futuretrust.vals.core.detection.TypeDetector;
import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.CadesUtils;
import eu.futuretrust.vals.core.signature.XadesUtils;
import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.exceptions.SignedObjectNotFoundException;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.utils.ProfileUtils;
import java.util.List;
import org.apache.commons.collections.CollectionUtils;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.cms.CMSSignedData;

public class SignedObjectExtractor {

  public SignedObject extract(final VerifyRequestType verifyRequest)
      throws SignedObjectNotFoundException, FormatException, ProfileNotFoundException, SignatureException {
    List<String> profiles = verifyRequest.getProfile();

    final byte[] signedObjectBytes = getSignedObjectBytes(verifyRequest);
    final SignedObjectFormat signedObjectFormat = getSignedObjectFormat(signedObjectBytes);
    final SignedObjectType signedObjectType = getSignedObjectType(signedObjectBytes,
        signedObjectFormat, ProfileUtils.getMainProfile(profiles));

    return new SignedObject(signedObjectBytes, signedObjectFormat, signedObjectType);
  }


  protected byte[] getSignedObjectBytes(final VerifyRequestType verifyRequest)
      throws SignedObjectNotFoundException {
    try
    {
      if (containsSignatureObject(verifyRequest))
      {
        return Base64.decode(verifyRequest.getSignatureObject().getBase64Signature().getValue());
      } else if (containsDocumentWithSignature(verifyRequest)) {
        return Base64.decode(verifyRequest.getOptionalInputs().getDocumentWithSignature().getDocument().getBase64Data().getValue());
      } else {
        throw new SignedObjectNotFoundException("No signed object found in the VerifyRequest",
            ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED);
      }
    } catch (Base64DecodingException e) {
      throw new SignedObjectNotFoundException("No signed object found in the VerifyRequest",
          ResultMajor.REQUESTER_ERROR, ResultMinor.NOT_SUPPORTED);
    }
  }

  protected SignedObjectFormat getSignedObjectFormat(final byte[] signedObject)
      throws FormatException {
    return FormatDetector.detect(signedObject);
  }

  private SignedObjectType getSignedObjectType(final byte[] signedObject,
      final SignedObjectFormat format, final Profile mainProfile) throws SignatureException {

    //TODO: switch on the profile, THEN on the format.
    //This will avoid possible confusion between XML used for XAdES and ERS, or CMS in CAdES, X.509 and ERS, etc.
    /*
    switch (mainProfile) {
    }
    */

    switch (format) {
      case XML:
        List<XMLSignature> signatures = XadesUtils.getXmlSignatures(signedObject);
        if (CollectionUtils.isEmpty(signatures)) {
          throw new SignatureException("No XML signature found");
        }
        return TypeDetector.detect(signatures.get(0));
      case CMS:
        CMSSignedData signedData = CadesUtils.getSignedData(signedObject);
        return TypeDetector.detect(signedData);
      case PDF:
        return SignedObjectType.ENVELOPED;
      case ASIC:
        return SignedObjectType.DETACHED;
      case X509:
        return SignedObjectType.CERTIFICATE;
      case ERS_CMS:
        return SignedObjectType.EVIDENCE_RECORD;
      default:
        throw new SignatureException("Signature format is not recognized");
    }
  }

  private boolean containsDocumentWithSignature(final VerifyRequestType verifyRequest) {
    return verifyRequest.getOptionalInputs() != null
            && verifyRequest.getOptionalInputs().getDocumentWithSignature() != null
            && verifyRequest.getOptionalInputs().getDocumentWithSignature().getDocument() != null
            && verifyRequest.getOptionalInputs().getDocumentWithSignature().getDocument()
            .getBase64Data() != null;
  }

  private boolean containsSignatureObject(final VerifyRequestType verifyRequest) {
    return verifyRequest.getSignatureObject() != null
        && verifyRequest.getSignatureObject().getBase64Signature() != null
        && verifyRequest.getSignatureObject().getBase64Signature().getValue() != null;
  }

}
