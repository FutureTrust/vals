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

package eu.futuretrust.vals.core.enums;

import java.util.Optional;

public enum SignedObjectType {
  ENVELOPED,
  ENVELOPING,
  DETACHED,

  ENVELOPING_DETACHED,
  ENVELOPED_DETACHED,

  ENVELOPED_ENVELOPING_DETACHED,

  EVIDENCE_RECORD,

  CERTIFICATE;

  public boolean isEnveloped() {
    return this == ENVELOPED
        || this == ENVELOPED_DETACHED
        || this == ENVELOPED_ENVELOPING_DETACHED;
  }

  public boolean isEnveloping() {
    return this == ENVELOPING
        || this == ENVELOPING_DETACHED
        || this == ENVELOPED_ENVELOPING_DETACHED;
  }

  public boolean isDetached() {
    return this == DETACHED
        || this == ENVELOPED_DETACHED
        || this == ENVELOPING_DETACHED
        || this == ENVELOPED_ENVELOPING_DETACHED;
  }

  public boolean isCertificate() {
    return this == CERTIFICATE;
  }

  public boolean isEvidenceRecord() {
    return this == EVIDENCE_RECORD;
  }

  public static Optional<SignedObjectType> fromBooleans(SignedObjectFormat signatureFormat,
      boolean isEnveloped, boolean isEnveloping,
      boolean isDetached) {
    // all booleans are FALSE => INDETERMINATE
    if (!isEnveloped && !isEnveloping && !isDetached) {
      return Optional.empty();
    }

    switch (signatureFormat) {
      case PDF:
        return getSignedObjectTypeForPDF(isEnveloped);
      case PKCS7:
        return getSignedObjectTypeForCMS(isEnveloping, isDetached);
      case XML:
        return getSignedObjectTypeForXML(isEnveloped, isEnveloping, isDetached);
      case X509:
        return getSignedObjectTypeForX509();
      case ERS_CMS:
        return getSignedObjectTypeForERS_CMS();
      default:
        return Optional.empty();
    }
  }

  private static Optional<SignedObjectType> getSignedObjectTypeForPDF(boolean isEnveloped) {
    if (isEnveloped) {
      return Optional.of(ENVELOPED);
    } else {
      return Optional.empty();
    }
  }


  private static Optional<SignedObjectType> getSignedObjectTypeForCMS(boolean isEnveloping,
      boolean isDetached) {
    // Cannot be enveloping & detached
    if (isEnveloping && isDetached) {
      return Optional.empty();
    } else if (isEnveloping) {
      return Optional.of(ENVELOPING);
    } else if (isDetached) {
      return Optional.of(DETACHED);
    } else {
      return Optional.empty();
    }
  }

  private static Optional<SignedObjectType> getSignedObjectTypeForXML(boolean isEnveloped,
      boolean isEnveloping,
      boolean isDetached) {
    // all booleans are TRUE => ENVELOPED_ENVELOPING_DETACHED
    if (isEnveloped && isEnveloping && isDetached) {
      return Optional.of(ENVELOPED_ENVELOPING_DETACHED);
    }

    // isEnveloped && isDetached => ENVELOPED_DETACHED
    else if (isEnveloped && !isEnveloping && isDetached) {
      return Optional.of(ENVELOPED_DETACHED);
    }
    // isEnveloping && isDetached => ENVELOPING_DETACHED
    else if (!isEnveloped && isEnveloping && isDetached) {
      return Optional.of(ENVELOPING_DETACHED);
    }
    // isEnveloping && isEnveloping => INDETERMINATE
    else if (isEnveloped && isEnveloping) {
      return Optional.empty();
    }

    // isEnveloped => ENVELOPED
    else if (isEnveloped) {
      return Optional.of(ENVELOPED);
    }
    // isEnveloping => ENVELOPING
    else if (isEnveloping) {
      return Optional.of(ENVELOPING);
    }
    // isDetached => DETACHED
    else {
      return Optional.of(DETACHED);
    }
  }

  private static Optional<SignedObjectType> getSignedObjectTypeForX509() {
    return Optional.of(CERTIFICATE);
  }

  private static Optional<SignedObjectType> getSignedObjectTypeForERS_CMS() {
    return Optional.of(EVIDENCE_RECORD);
  }

}
