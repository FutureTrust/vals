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

package eu.futuretrust.vals.protocol.enums;

public enum SignatureProperties
{

  XMLDSIG_SIGNATURE_PROPERTIES("http://www.w3.org/2000/09/xmldsig#SignatureProperties"),
  ETSI_SIGNATURE_PROPERTIES("http://uri.etsi.org/01903#SignedProperties");

  private final String type;

  SignatureProperties(String type) {
    this.type = type;
  }

  public static boolean contains(String type) {
    for (SignatureProperties c : SignatureProperties.values()) {
      if (c.type.equals(type)) {
        return true;
      }
    }
    return false;
  }
}
