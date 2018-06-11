/*
 * Copyright (c) 2017 European Commission.
 *
 *  Licensed under the EUPL, Version 1.1 or – as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
 *  You may not use this work except in compliance with the Licence.
 *  You may obtain a copy of the Licence at: https://joinup.ec.europa.eu/software/page/eupl5
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 */

package eu.futuretrust.vals.core.x509;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class X509CVParameters
{
  private Set<Option> options = Collections.emptySet();

  private X509CVParameters() {
  }

  public X509CVParameters(Set<Option> options) {
    this.options = options;
  }

  public void setOptions(Set<Option> opts){
    this.options = (opts == null? Collections.emptySet() : new HashSet<>(opts));
  }

  public Set<Option> getOptions(){
    return Collections.unmodifiableSet(this.options);
  }

  /**
   * Validation options to cope with policy requirements
   *
   * EnuRevReqType = [ crlCheck | ocspCheck | bothCheck | eitherCheck | noCheck ]
   *
   */
  public enum Option{
    /**
     * Perform CRL revocation check for the end-entity certificate
     */
    CRL_CHECK_EE,

    /**
     * Perform OCSP revocation check for the end-entity certificate
     */
    OCSP_CHECK_EE,

    /**
     * Perform both OCSP AND CRL revocation check for the end-entity certificate
     */
    BOTH_CHECK_EE,

    /**
     * Perform CRL revocation check for CA certificate(s)
     */
    CRL_CHECK_CA,

    /**
     * Perform OCSP revocation check for CA certificate(s)
     */
    OCSP_CHECK_CA,

    /**
     * Perform both OCSP AND CRL revocation check for the CA certificate(s)
     */
    BOTH_CHECK_CA,
  }
}
