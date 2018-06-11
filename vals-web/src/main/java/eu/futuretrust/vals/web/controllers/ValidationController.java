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

package eu.futuretrust.vals.web.controllers;

import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.protocol.enums.DSSResponseType;
import eu.futuretrust.vals.protocol.exceptions.ProfileNotFoundException;
import eu.futuretrust.vals.protocol.exceptions.VerifyRequestException;
import eu.futuretrust.vals.web.services.jaxb.JaxbService;
import eu.futuretrust.vals.web.services.validation.ValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/validation")
public class ValidationController {

  private static final Logger LOGGER = LoggerFactory.getLogger(ValidationController.class);

  private final ValidationService validationService;
  private final JaxbService jaxbService;

  @Autowired
  public ValidationController(ValidationService validationService,
      JaxbService jaxbService) {
    this.validationService = validationService;
    this.jaxbService = jaxbService;
  }

  @RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<VerifyResponseType> jsonValidate(
      @RequestBody VerifyRequestType verifyRequest) {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Verify Response generation (JSON format)");
    }
    /* generate Verify Response */
    VerifyResponseType verifyResponse;
    try {
      verifyResponse = validationService.validate(verifyRequest, DSSResponseType.JSON);
    } catch (VerifyRequestException | ProfileNotFoundException e) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

    /* Verify Response should not be null */
    if (verifyResponse == null) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    return ResponseEntity.ok(verifyResponse);
  }

  @RequestMapping(method = RequestMethod.POST, consumes = MediaType.APPLICATION_XML_VALUE, produces = MediaType.APPLICATION_XML_VALUE)
  public ResponseEntity<byte[]> xmlValidate(@RequestBody VerifyRequestType verifyRequest) {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.info("Verify Response generation (XML format)");
    }
    /* generate Verify Response */
    VerifyResponseType verifyResponse;
    try {
      verifyResponse = validationService.validate(verifyRequest, DSSResponseType.XML);
    } catch (VerifyRequestException | ProfileNotFoundException e) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
    }

    /* Verify Response should not be null */
    if (verifyResponse == null) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    try {
      return ResponseEntity.ok(jaxbService.marshalVerifyResponse(verifyResponse));
    } catch (Exception e) {
      if (LOGGER.isErrorEnabled()) {
        LOGGER.error(e.getMessage());
      }
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }
  }


}
