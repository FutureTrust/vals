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

package eu.futuretrust.vals.core.etsi.esi.enums;

/**
 *
 * The values that remain here are linked with the policy elements
 * Set of values chosen in-house to keep track of signature validation and policy enforcement results
 *
 */
public enum Evaluation {
  FORMAT_CHECK,
  EXCLUDED_SUBTREE,
  PERMITTED_SUBTREE,
  TIMESTAMP,
  TIMESTAMP_TRUST_POINTS,
  TIMESTAMP_SIGNATURE_DELAY,
  TIMESTAMP_CAUTION_PERIOD,
  ROLE_MANDATED,
  CLAIMED_ROLE,
  CERTIFIED_ROLE,
  CERTIFICATION_PATH,
  SIGNING_TIME,
  SIGNED_QUALIFYING_PROPERTIES,
  UNSIGNED_QUALIFYING_PROPERTIES,
  MANDATED_CERTIFICATE_REF,
  MANDATED_CERTIFICATE_INFO,
  SIGNER_TRUST_TREE,
  SIGNER_REVOCATION_REQ,
  ID_SIGNERS_CERTIFICATE,
  ISSUER_SERIAL,
  INITIAL_VALIDATION_CONTEXT,
  SIGNATURE_VERIFICATION,
  SIGNER_ALGORITHM_CONSTRAINTS,
  TSA_ALGORITHM_CONSTRAINTS,
  AA_ALGORITHM_CONSTRAINTS,
  EE_ALGORITHM_CONSTRAINTS,
  CA_ALGORITHM_CONSTRAINTS,
  CERTIFICATE_VALUES_TSA,
  CERTIFICATE_VALUES_SIGNER
}
