package eu.futuretrust.vals.web.controllers;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.core.signature.exceptions.FormatException;
import eu.futuretrust.vals.core.signature.exceptions.SignatureException;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.protocol.exceptions.InputDocumentException;
import eu.futuretrust.vals.protocol.exceptions.VerifyRequestException;
import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import eu.futuretrust.vals.web.services.jaxb.JaxbService;
import eu.futuretrust.vals.web.services.request.VerifyRequestService;
import eu.futuretrust.vals.web.utils.MultipartFileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/request")
public class VerifyRequestController
{

  private final static Logger LOGGER = LoggerFactory.getLogger(VerifyRequestController.class);
  private final VerifyRequestService verifyRequestService;
  private JaxbService jaxbService;

  @Autowired
  public VerifyRequestController(final VerifyRequestService verifyRequestService,
                                 final JaxbService jaxbService) {
    this.verifyRequestService = verifyRequestService;
    this.jaxbService = jaxbService;
  }

  @PostMapping(produces = MediaType.APPLICATION_XML_VALUE)
  public ResponseEntity<byte[]> createXmlVerifyRequest(
          @RequestParam("signature")MultipartFile signature,
          @RequestParam(value = "documents", required = false) MultipartFile[] documents) {

    if(! MultipartFileUtils.valid(signature)
            || ! MultipartFileUtils.valid(documents)) {
      return ResponseEntity.badRequest().build();
    }

    VerifyRequestType verifyRequest;

    try {
      verifyRequest = generateVerifyRequest(signature, documents);
    } catch (final Exception e) {
      return ResponseEntity.badRequest().build();
    }

    try {
      return ResponseEntity.ok(jaxbService.marshalVerifyRequest(verifyRequest));
    } catch (final Exception e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }
  }

  @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<VerifyRequestType> createJsonVerifyRequest(
          @RequestParam("signature") MultipartFile signature,
          @RequestParam(value = "documents", required = false) MultipartFile[] documents) {

    if (! MultipartFileUtils.valid(signature)) {
      return ResponseEntity.badRequest().build();
    }
    //boolean docsVald = MultipartFileUtils.valid(documents);
    if (! MultipartFileUtils.valid(documents)) {
      return ResponseEntity.badRequest().build();
    }

    VerifyRequestType verifyRequest;
    try {
      verifyRequest = generateVerifyRequest(signature, documents);
    } catch (Exception e) {
      LOGGER.error("Error", e);
      return ResponseEntity.badRequest().build();
    }

    return ResponseEntity.ok(verifyRequest);
  }

  private VerifyRequestType generateVerifyRequest(final MultipartFile signature,
                                                  final MultipartFile[] documents)
          throws SignatureException, InputDocumentException, VerifyRequestException
  {
    /* convert MultipartFile to byte[] (signature) */
    byte[] bytesSignature;
    try {
      bytesSignature = signature.getBytes();
    } catch (IOException e) {
      String errorMessage = "The signature file cannot be read";
      throw new SignatureException(errorMessage);
    }

    /* double check to make sure that the signature exists */
    if (bytesSignature == null) {
      String errorMessage = "The signature file cannot be read";
      throw new SignatureException(errorMessage);
    }

    /* convert MultipartFile to byte[] (documents) */
    List<InputDocument> inputDocuments;
    try {
      inputDocuments = MultipartFileUtils.toInputDocuments(documents);
    } catch (IOException e) {
      String errorMessage = "One (or more) document(s) cannot be read";
      throw new InputDocumentException(errorMessage, ResultMajor.REQUESTER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    /* generate Verify Request */
    VerifyRequestType verifyRequest;
    try {
      verifyRequest = verifyRequestService.generate(bytesSignature, inputDocuments);
    } catch (SignatureException | FormatException e) {
      String errorMessage = "The VerifyRequest cannot be generated";
      throw new VerifyRequestException(errorMessage, ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    /* double check to make sure that the verify request is not null */
    if (verifyRequest == null) {
      String errorMessage = "The VerifyRequest cannot be generated";
      throw new VerifyRequestException(errorMessage, ResultMajor.RESPONDER_ERROR, ResultMinor.GENERAL_ERROR);
    }

    return verifyRequest;
  }
}
