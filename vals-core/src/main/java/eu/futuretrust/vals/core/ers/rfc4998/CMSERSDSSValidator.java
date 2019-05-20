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

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.futuretrust.vals.common.enums.ResultMajor;
import eu.futuretrust.vals.common.enums.ResultMinor;
import eu.futuretrust.vals.common.exceptions.VerifyRequestException;
import eu.futuretrust.vals.core.enums.ERSSignatureType;
import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.ers.ERSDSSValidator;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.Base64DataType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentHashType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.DocumentType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.InputDocumentsType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.DataGroup;
import org.bouncycastle.asn1.cms.EvidenceRecord;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.ArchiveTimeStampValidationException;
import org.bouncycastle.cms.EvidenceRecordVerifier;
import org.bouncycastle.cms.PartialHashTreeVerificationException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CMSERSDSSValidator extends ERSDSSValidator {

  private final EvidenceRecordVerifier verifier;

  public CMSERSDSSValidator(final CertificateVerifier certificateVerifier,
                            final EvidenceRecordVerifier evidenceRecordVerifier) {
    super(certificateVerifier);
    this.verifier = evidenceRecordVerifier;
  }

  public VerifyResponseType validate(final VerifyRequestType verifyRequest) throws VerifyRequestException {
    VerifyResponseType verifyResponse = ObjectFactoryUtils.FACTORY_ETSI_119_442.createVerifyResponseType();
    if (verifyRequest == null || verifyRequest.getSignatureObject() == null) {
      throw new VerifyRequestException("Invalid verify request", ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
    }
    // Validate request
    validateVerifyRequest(verifyRequest);

    Base64DataType base64Signature = verifyRequest.getSignatureObject().getBase64Signature();
    String mimeType = base64Signature.getMimeType();
    if (StringUtils.equalsIgnoreCase(mimeType, SignedObjectFormat.ERS_CMS.getMimeTypes()[0])) {
      try {
        InputDocumentsType inputDocuments = verifyRequest.getInputDocuments();
        List<DocumentType> documents = inputDocuments.getDocument();
        List<DocumentHashType> documentHashTypes = inputDocuments.getDocumentHash();

        // Generate evidence record instance
        final EvidenceRecord evidenceRecord = getEvidenceRecord(verifyRequest);
        AlgorithmIdentifier algorithmIdentifier;
        Object value;
        if (!Utils.isCollectionEmpty(documentHashTypes)) {
          List<byte[]> documentHashes = new ArrayList<>();
          for (DocumentHashType documentHashType : documentHashTypes) {
            documentHashes.add(Base64.decode(documentHashType.getDigestInfos().get(0).getDigestValue()));
          }
          value = (documentHashes.size() > 1) ? documentHashes : documentHashes.get(0);
          algorithmIdentifier = findDigestAlgorithm(documentHashTypes);
        } else {
          List<byte[]> documentsByteArr = new ArrayList<>();
          for (DocumentType documentType : documents) {
            documentsByteArr.add(Base64.decode(documentType.getBase64Data().getValue()));
          }
          value = (documents.size() > 1) ? new DataGroup(documentsByteArr) : documentsByteArr.get(0);
          algorithmIdentifier = null;
        }
        verifier.validate(evidenceRecord, value, algorithmIdentifier);
      } catch (IOException | CertificateException | TSPException | NoSuchAlgorithmException
          | PartialHashTreeVerificationException | OperatorCreationException
          | ArchiveTimeStampValidationException e) {
        // Validation failed
        ResultType result = ObjectFactoryUtils.FACTORY_OASIS_CORE_2.createResultType();
        result.setResultMajor(ResultMajor.REQUESTER_ERROR.getURI());
        result.setResultMinor(ResultMinor.GENERAL_ERROR.getURI());
        verifyResponse.setResult(result);
        return verifyResponse;
      }
    }
    // Validation success
    ResultType resultType = getResult();
    resultType.setResultMinor(ResultMinor.ON_ALL_DOCUMENTS.getURI());
    verifyResponse.setResult(resultType);
    return verifyResponse;
  }

  private void checkDetachedDocumentsValid(final List<DocumentType> documents) throws VerifyRequestException {
    //If more than one InputDocument child element is present the ID attributes of these elements MUST be present and
    // contain distinct values.
    if (documents.size() > 1) {
      final Set<String> ids = new HashSet<>();
      for (DocumentType documentType : documents) {
        ids.add(documentType.getID());
      }
      if (ids.size() < documents.size()) {
        throw new VerifyRequestException("Document Id is required", ResultMajor.REQUESTER_ERROR,
            ResultMinor.INVALID_DOCUMENT_ID);
      }
    }
  }

  private void checkDetachedDocumentHashesValid(final List<DocumentHashType> documentHashTypes)
    throws VerifyRequestException {
    if (Utils.isCollectionNotEmpty(documentHashTypes)) {
      final Set<String> ids = new HashSet<>();
      for (DocumentHashType documentHashType : documentHashTypes) {
        ids.add(documentHashType.getID());
        if(Utils.isCollectionEmpty(documentHashType.getDigestInfos())) {
          throw new VerifyRequestException("Digest Info required", ResultMajor.REQUESTER_ERROR,
              ResultMinor.GENERAL_ERROR);
        }
      }
      if (ids.size() < documentHashTypes.size()) {
        throw new VerifyRequestException("Document Id is required", ResultMajor.REQUESTER_ERROR,
            ResultMinor.INVALID_DOCUMENT_ID);
      }
    }
  }


  private void validateInputDocuments(final InputDocumentsType inputDocuments) throws VerifyRequestException {
    List<DocumentType> documents = inputDocuments.getDocument();
    List<DocumentHashType> documentHashes = inputDocuments.getDocumentHash();
    if (Utils.isCollectionEmpty(documents) && Utils.isCollectionEmpty(documentHashes)) {
      throw new VerifyRequestException("Document or document hash required",
          ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
    }
  }

  /**
   * Verifies whether the request actually relates to an Evidence Record, and matches the profile defined under the
   * Evidence Record Verification Profile of the OASIS Digital Signature Service Version 0.1.
   *
   * @param verifyRequest verify request
   */
  private void validateVerifyRequest(final VerifyRequestType verifyRequest) throws VerifyRequestException {
    String signatureType = ERSSignatureType.RFC4998.getUrn();
    if (!verifyRequest.getProfile().contains(Profile.ERS.getUri()) ||
        verifyRequest.getInputDocuments() == null ||
        !signatureType.equalsIgnoreCase(verifyRequest.getOptionalInputs().getSignatureType())) {
      throw new VerifyRequestException("Invalid profile or signature type", ResultMajor.REQUESTER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    if (verifyRequest.getOptionalInputs() != null &&
        verifyRequest.getOptionalInputs().getAddTimestamp() != null) {
      throw new VerifyRequestException("OptionalInputs/AddTimestamp element MUST NOT be used with this profile", ResultMajor.REQUESTER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }

    validateInputDocuments(verifyRequest.getInputDocuments());
    checkDetachedDocumentsValid(verifyRequest.getInputDocuments().getDocument());
    checkDetachedDocumentHashesValid(verifyRequest.getInputDocuments().getDocumentHash());
  }

  /**
   * @param verifyRequestType verify request
   * @return EvidenceRecord Evidence record instance
   */
  private EvidenceRecord getEvidenceRecord(final VerifyRequestType verifyRequestType) throws VerifyRequestException {
    try {
      byte[] value = Base64.decode(verifyRequestType.getSignatureObject().getBase64Signature().getValue());
      return EvidenceRecord.getInstance(value);
    } catch (final IllegalArgumentException e) {
      throw new VerifyRequestException("Invalid evidence record", ResultMajor.REQUESTER_ERROR,
          ResultMinor.GENERAL_ERROR);
    }
  }

  private AlgorithmIdentifier findDigestAlgorithm(List<DocumentHashType> documentHashTypes) {
    AlgorithmIdentifier algorithmIdentifier = null;
    if (Utils.isCollectionNotEmpty(documentHashTypes) &&
        Utils.isCollectionNotEmpty(documentHashTypes.get(0).getDigestInfos())) {
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.forName(documentHashTypes.get(0)
          .getDigestInfos().get(0).getDigestMethod(), DigestAlgorithm.SHA256);
      algorithmIdentifier = new AlgorithmIdentifier(
          new ASN1ObjectIdentifier(digestAlgorithm.getOid()));
    }
    return algorithmIdentifier;
  }

  private ResultType getResult() {
    ResultType result = ObjectFactoryUtils.FACTORY_OASIS_CORE_2.createResultType();
    result.setResultMajor(ResultMajor.SUCCESS.getURI());
    return result;
  }
}