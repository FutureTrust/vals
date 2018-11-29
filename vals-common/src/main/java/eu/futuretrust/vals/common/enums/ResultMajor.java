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

package eu.futuretrust.vals.common.enums;

public enum ResultMajor
{
  /**
   * The protocol executed successfully.
   */
  SUCCESS("urn:oasis:names:tc:dss:1.0:resultmajor:Success"),

  /**
   * The request could not be satisfied due to an error on the part of the requester.
   */
  REQUESTER_ERROR("urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError"),

  /**
   * The request could not be satisfied due to an error on the part of the responder.
   */
  RESPONDER_ERROR("urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError"),

  /**
   * The request could not be satisfied due to insufficient information.
   */
  INSUFFICIENT_INFORMATION("urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation");

  private String uri;


  ResultMajor(String uri) {
    this.uri = uri;
  }

  public String getURI() {
    return this.uri;
  }
}
