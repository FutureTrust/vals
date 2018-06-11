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

import java.util.List;

public class InputDocumentHash extends AbstractDocument {

  private List<HashedDocument> hashedDocuments;

  public List<HashedDocument> getHashedDocuments() {
    return hashedDocuments;
  }

  public void setHashedDocuments(
      List<HashedDocument> hashedDocuments) {
    this.hashedDocuments = hashedDocuments;
  }

  public InputDocumentHash(String name, List<HashedDocument> hashedDocuments) {
    super(name);
    this.hashedDocuments = hashedDocuments;
  }

  public InputDocumentHash(List<HashedDocument> hashedDocuments) {
    super();
    this.hashedDocuments = hashedDocuments;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    InputDocumentHash that = (InputDocumentHash) o;

    return hashedDocuments != null ? hashedDocuments.equals(that.hashedDocuments)
        : that.hashedDocuments == null;
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + (hashedDocuments != null ? hashedDocuments.hashCode() : 0);
    return result;
  }
}
