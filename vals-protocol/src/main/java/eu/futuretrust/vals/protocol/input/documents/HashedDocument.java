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

package eu.futuretrust.vals.protocol.input.documents;

import java.util.Arrays;

public class HashedDocument {

  private byte[] hashedContent;
  private String hashingAlgorithm;

  public HashedDocument(String hashingAlgorithm, byte[] hashedContent){
    this.hashedContent = hashedContent;
    this.hashingAlgorithm = hashingAlgorithm;
  }

  public byte[] getHashedContent() {
    return hashedContent;
  }

  public void setHashedContent(byte[] hashedContent) {
    this.hashedContent = hashedContent;
  }

  public String getHashingAlgorithm() {
    return hashingAlgorithm;
  }

  public void setHashingAlgorithm(String hashingAlgorithm) {
    this.hashingAlgorithm = hashingAlgorithm;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    HashedDocument that = (HashedDocument) o;

    if (!Arrays.equals(hashedContent, that.hashedContent)) {
      return false;
    }
    return hashingAlgorithm != null ? hashingAlgorithm.equals(that.hashingAlgorithm)
        : that.hashingAlgorithm == null;
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(hashedContent);
    result = 31 * result + (hashingAlgorithm != null ? hashingAlgorithm.hashCode() : 0);
    return result;
  }

}
