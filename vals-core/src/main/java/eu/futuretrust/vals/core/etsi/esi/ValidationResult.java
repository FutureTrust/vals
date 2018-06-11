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

package eu.futuretrust.vals.core.etsi.esi;


import eu.futuretrust.vals.core.etsi.esi.enums.MainIndication;
import eu.futuretrust.vals.core.etsi.esi.enums.SubIndication;
import java.util.List;

public class ValidationResult
{
  private MainIndication mainIndication;
  private SubIndication subIndication;
  private List<Object> validationData;

  public ValidationResult(MainIndication mainIndication) {
    this.mainIndication = mainIndication;
  }

  public ValidationResult(MainIndication mainIndication, SubIndication subIndication) {
    this(mainIndication);
    this.subIndication = subIndication;
  }

  public ValidationResult(MainIndication mainIndication, List<Object> validationData) {
    this(mainIndication, null, validationData);
  }

  public ValidationResult(MainIndication mainIndication, SubIndication subIndication, List<Object> validationData) {
    this(mainIndication, subIndication);
    this.validationData = validationData;
  }

  public MainIndication getMainIndication() {
    return mainIndication;
  }

  public void setMainIndication(MainIndication mainIndication) {
    this.mainIndication = mainIndication;
  }

  public SubIndication getSubIndication() {
    return subIndication;
  }

  public void setSubIndication(SubIndication subIndication) {
    this.subIndication = subIndication;
  }

  public List<Object> getValidationData() {
    return validationData;
  }

  public boolean addValidationData(Object obj) {
    return validationData.add(obj);
  }

  public boolean hasValidationData() {
    return validationData.isEmpty();
  }

  /*public void setValidationData(List<Object> validationData) {
    this.validationData = validationData;
  }*/

  @Override
  public String toString() {
    return "ValidationResult{" +
      "mainIndication=" + mainIndication +
      ", subIndication=" + subIndication +
      ", validationData=" + validationData +
      '}';
  }
}
