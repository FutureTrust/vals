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

package eu.futuretrust.vals.core.ers.rfc4998;

import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.futuretrust.vals.common.exceptions.VerifyRequestException;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.ers.ERSDSSValidator;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.*;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.EvidenceRecordVerifier;
import org.bouncycastle.asn1.cms.EvidenceRecord;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CMSERSDSSValidator extends ERSDSSValidator
{

  private final EvidenceRecordVerifier verifier;

  public CMSERSDSSValidator(final CertificateVerifier certificateVerifier, final EvidenceRecordVerifier evidenceRecordVerifier)
  {
    super(certificateVerifier);
    this.verifier = evidenceRecordVerifier;
  }

  public VerifyResponseType validate(final VerifyRequestType verifyRequest) throws VerifyRequestException
  {

    if (verifyRequest == null || verifyRequest.getSignatureObject() == null) {
      throw new IllegalArgumentException("Invalid verifyRequest etc."); //todo
    }

    else
    {
      Base64DataType base64Signature = verifyRequest.getSignatureObject().getBase64Signature();
      String mimeType = base64Signature.getMimeType();

      if (StringUtils.equalsIgnoreCase(mimeType, SignedObjectFormat.BYTES.name())) {

        final EvidenceRecord er = getEvidenceRecord(verifyRequest);

        InputDocumentsType inputDocuments = verifyRequest.getInputDocuments();
        List<DocumentType> documents = inputDocuments.getDocument();
        List<DocumentHashType> documentHashes = inputDocuments.getDocumentHash();


      }

      verifyRequest.getOptionalInputs();

      return null;
    }
  }

  private void validateInputDocuments(final InputDocumentsType inputDocuments) {

    List<DocumentType> documents = inputDocuments.getDocument();
    List<DocumentHashType> documentHashes = inputDocuments.getDocumentHash();

  }

  private void checkDetachedDocumentsValid(final List<DocumentType> documents) throws VerifyRequestException
  {
    //If more than one InputDocument child element is present the ID attributes of these elements MUST be present and
    // contain distinct values.
    if (documents.size() > 1)
    {
      final Set<String> ids = new HashSet<>();
      documents.stream()
              .map(doc -> doc.getID())
              .map(id -> ids.add(id));
      if (ids.size() < documents.size())
      {
        throw new VerifyRequestException("", eu.futuretrust.vals.common.enums.ResultMajor.REQUESTER_ERROR, eu.futuretrust.vals.common.enums.ResultMinor.GENERAL_ERROR);
      }
    }
  }

  /**
   * Verifies whether the request actually relates to an Evidence Record, and matches the profile defined under the
   * Evidence Record Verification Profile of the OASIS Digital Signature Service Version 0.1.
   * @param verifyRequest
   */
  private void validateVerifyRequest(final VerifyRequestType verifyRequest) {


  }

  /**
   *
   * @param verifyRequestType
   * @return
   */
  private EvidenceRecord getEvidenceRecord(final VerifyRequestType verifyRequestType) throws VerifyRequestException
  {

    try
    {
      byte[] value = verifyRequestType.getSignatureObject().getBase64Signature().getValue();
      return EvidenceRecord.getInstance(value);
    } catch (final IllegalArgumentException e) {
      throw new VerifyRequestException("", eu.futuretrust.vals.common.enums.ResultMajor.REQUESTER_ERROR, eu.futuretrust.vals.common.enums.ResultMinor.GENERAL_ERROR);
    }
  }

}