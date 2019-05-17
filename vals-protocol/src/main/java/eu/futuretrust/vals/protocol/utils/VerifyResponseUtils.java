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

package eu.futuretrust.vals.protocol.utils;

import eu.futuretrust.vals.core.enums.Iso6391;
import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyRequestType;
import eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.VerifyResponseType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.InternationalStringType;
import eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ResultType;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;

public final class VerifyResponseUtils {

  private VerifyResponseUtils() {
  }

  public static VerifyResponseType getVerifyResponse(final ResultMajor resultMajor,
      final ResultMinor resultMinor, final String message, final VerifyRequestType verifyRequest) {
    return getVerifyResponse(resultMajor.getURI(),
        (resultMinor != null ? resultMinor.getURI() : null), message, verifyRequest);
  }

  public static VerifyResponseType getVerifyResponse(final String resultMajor,
      final String resultMinor,
      final String message,
      final VerifyRequestType verifyRequest) {

    final ResultType result = ObjectFactoryUtils.FACTORY_OASIS_CORE_2.createResultType();
    result.setResultMajor(resultMajor);
    result.setResultMinor(resultMinor);

    if (message != null) {
      final InternationalStringType resultMessage = getResultMessage(message);
      result.setResultMessage(resultMessage);
    }

    final VerifyResponseType verifyResponse = ObjectFactoryUtils.FACTORY_ETSI_119_442
        .createVerifyResponseType();
    if (verifyRequest != null && verifyRequest.getRequestID() != null) {
      verifyResponse.setRequestID(verifyRequest.getRequestID());
    }

    verifyResponse.setResult(result);
    return verifyResponse;
  }

  public static InternationalStringType getResultMessage(String message) {
    final InternationalStringType resultMessage = ObjectFactoryUtils.FACTORY_OASIS_CORE_2
        .createInternationalStringType();
    resultMessage.setValue(message);
    resultMessage.setLang(Iso6391.ENGLISH.getIsoCode());
    return resultMessage;
  }
}
