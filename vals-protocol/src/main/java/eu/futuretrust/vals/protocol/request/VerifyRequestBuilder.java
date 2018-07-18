package eu.futuretrust.vals.protocol.request;

import eu.futuretrust.vals.core.enums.Profile;
import eu.futuretrust.vals.core.enums.SignedObjectType;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.UseSignatureValidationPolicyType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.OptionalInputsVerifyType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.*;
import eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.ReturnVerificationReport;
import eu.futuretrust.vals.protocol.enums.ReportDetailLevel;
import eu.futuretrust.vals.protocol.enums.SignatureFormat;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import org.bouncycastle.util.encoders.Base64;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public abstract class VerifyRequestBuilder
{

    /**
     * signature file to be validated
     */
    protected byte[] signature;

    /**
     * policy URI
     */
    protected String policy;

    /**
     * documents covered by the signature
     */
    protected Set<InputDocument> documents;

    /**
     * Verify Request to generate
     */
    private VerifyRequestType verifyRequest;

    VerifyRequestBuilder(byte[] signature) {
      this.signature = signature;
      this.verifyRequest = new VerifyRequestType();
      this.policy = null;
      this.documents = null;
    }

    /**
     * Generate a Verify Request based on the signature (and other inputs)
     *
     * @return Verify Request generated
     * @throws SignatureException whenever the signature is invalid
     */
    public abstract VerifyRequestType generate() throws SignatureException;

    /**
     * Set all attributes that are common to all formats (e.g. XadES, CadES, PadES)
     */
    protected void setCommonDefaultAttributes() {
      setRequestID();
      setDefaultProfile();
      setReturnVerificationReport();
      setReturnVerificationTimeInfo();
      setReturnSignVerificationReport();
    }

    /**
     * Get the format of the signature (e.g. XadES, CadES, PadES)
     *
     * @return format of the signature
     */
    public abstract SignatureFormat getSignatureFormat();

    /**
     * Get the type of the signature (e.g. enveloped, enveloping, detached)
     *
     * @return type of the signature
     */
    public abstract SignedObjectType getSignatureType() throws SignatureException;

    /**
     * @return verify request
     */
    protected VerifyRequestType getVerifyRequest() {
      return this.verifyRequest;
    }

    /**
     * add the default profile which is used as an identifier notifying that the request has been
     * built using the profile defined by ETSI 119 442
     */
    protected void setDefaultProfile() {
      String defaultProfile = Profile.DSS_CORE_2.getUri();
      verifyRequest.getProfile().add(defaultProfile);
    }

    /**
     * add the element ReturnVerificationReport in order to ask the server for returning the detailed
     * validation report
     */
    protected void setReturnVerificationReport() {
      checkOptionalInputsInstance();
      ReturnVerificationReport returnVerificationReport = new ReturnVerificationReport();
      returnVerificationReport.setIncludeVerifier(true);
      returnVerificationReport.setIncludeCertificateValues(false);
      returnVerificationReport.setIncludeRevocationValues(false);
      returnVerificationReport.setExpandBinaryValues(false);
      returnVerificationReport.setReportDetailLevel(ReportDetailLevel.ALL_DETAILS.getURI());
      verifyRequest.getOptionalInputs().setReturnVerificationReport(returnVerificationReport);
    }

    /**
     * add the element ReturnVerificationTimeInfo in order to ask the server for returning an
     * indication of the validation time.
     */
    protected void setReturnVerificationTimeInfo() {
      verifyRequest.getOptionalInputs().setReturnVerificationTimeInfo(true);
    }

    /**
     * add the request ID which is used for correlating requests and responses to the verify request
     */
    protected void setRequestID() {
      String id = UUID.randomUUID().toString();
      verifyRequest.setRequestID(id);
    }

    protected void setReturnSignVerificationReport() {
      verifyRequest.getOptionalInputs().setSignVerificationReport(true);
    }

    /**
     * add a Document into the list of Document in Input Documents
     *
     * @param document document to be added
     */
    protected void addInputDocuments(DocumentType document) {
      checkInputDocumentsInstance();
      verifyRequest.getInputDocuments().getDocument().add(document);
    }

    /**
     * add a Transformed Data into the list of Transformed Data in Input Documents
     *
     * @param transformedData transformed data to be added
     */
    protected void addInputDocuments(TransformedDataType transformedData) {
      checkInputDocumentsInstance();
      verifyRequest.getInputDocuments().getTransformedData().add(transformedData);
    }

    /**
     * add a Document Hash into the list of Document Hash in Input Documents
     *
     * @param documentHash document hash to be added
     */
    protected void addInputDocuments(DocumentHashType documentHash) {
      checkInputDocumentsInstance();
      verifyRequest.getInputDocuments().getDocumentHash().add(documentHash);
    }

    /**
     * add the signature policy to the verify request
     *
     * @param signaturePolicyURI policy URI to be added
     */
    protected void setSignaturePolicy(String signaturePolicyURI) {
      checkOptionalInputsInstance();
      UseSignatureValidationPolicyType useSignatureValidationPolicyType = new UseSignatureValidationPolicyType();
      useSignatureValidationPolicyType.setSignatureValidationPolicyID(signaturePolicyURI);
      useSignatureValidationPolicyType.getSignaturePolicyLocation().add(signaturePolicyURI);
      verifyRequest.getOptionalInputs()
              .setUseSignatureValidationPolicy(useSignatureValidationPolicyType);
    }

    /**
     * get the base64 data representation of the signature
     *
     * @param mimeType Mime Type of the signature
     */
    protected Base64DataType getBase64Data(String mimeType) {
      Base64DataType base64DataType = new Base64DataType();
      base64DataType.setValue(Base64.encode(signature));
      if (mimeType != null) {
        base64DataType.setMimeType(mimeType);
      }
      return base64DataType;
    }


    /**
     * set Document with signature attribute
     *
     * @param base64DataSignature base64 representation of the signature document
     */
    protected void setDocumentWithSignature(Base64DataType base64DataSignature) {
      checkOptionalInputsInstance();
      DocumentWithSignatureType documentWithSignature = new DocumentWithSignatureType();
      DocumentType documentType = new DocumentType();
      documentType.setBase64Data(base64DataSignature);
      documentWithSignature.setDocument(documentType);
      verifyRequest.getOptionalInputs().setDocumentWithSignature(documentWithSignature);
    }

    /**
     * set Signature object attribute
     *
     * @param base64DataSignature base64 representation of the signature object
     */
    protected void setSignatureObject(Base64DataType base64DataSignature) {
      SignatureObjectType signatureObject = new SignatureObjectType();
      signatureObject.setBase64Signature(base64DataSignature);
      verifyRequest.setSignatureObject(signatureObject);
    }

    /**
     * set VerifyManifests field to "true", meaning that the Signature contains one or more Manifest
     */
    protected void setVerifyManifestsToTrue() {
      checkOptionalInputsInstance();
      verifyRequest.getOptionalInputs().setVerifyManifests(true);
    }

    /**
     * Make sure that the input documents object has been instantiated
     */
    private void checkInputDocumentsInstance() {
      if (verifyRequest.getInputDocuments() == null) {
        InputDocumentsType inputDocuments = new InputDocumentsType();
        verifyRequest.setInputDocuments(inputDocuments);
      }
    }

    /**
     * Make sure that the optional inputs object has been instantiated
     */
    private void checkOptionalInputsInstance() {
      if (verifyRequest.getOptionalInputs() == null) {
        OptionalInputsVerifyType optionalInputs = new OptionalInputsVerifyType();
        verifyRequest.setOptionalInputs(optionalInputs);
      }
    }

    /**
     * only getter, the signature should not be set by user
     *
     * @return the signed document
     */
    public byte[] getSignature() {
      return signature;
    }

    /**
     * @return policy
     */
    public String getPolicy() {
      return policy;
    }

    /**
     * set the policy
     *
     * @param policy policy uri
     */
    public void setPolicy(String policy) {
      this.policy = policy;
    }

    /**
     * @return input documents
     */
    public Set<InputDocument> getDocuments() {
      return documents;
    }

    /**
     * set the list of documents
     *
     * @param documents list of documents
     */
    public void setDocuments(List<InputDocument> documents) {
      if (documents != null && !documents.isEmpty()) {
        this.documents = new HashSet<>(documents);
      }
    }

    /**
     * add a new document into the list of documents
     *
     * @param document document to be added
     */
    public void addDocument(InputDocument document) {
      if (document != null) {
        if (this.documents == null) {
          this.documents = new HashSet<>();
        }
        this.documents.add(document);
      }
    }

}

