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

package eu.futuretrust.vals.protocol.exceptions;

import eu.futuretrust.vals.core.enums.ResultMajor;
import eu.futuretrust.vals.core.enums.ResultMinor;

/**
 * A CommonException is an Exception which encapsulates a ResultMajor and a ResultMinor in order to
 * return a Result which conforms with ETSI TS 119 442 and which indicates that a problem occured
 * while attempting to apply the protocol ETSI TS 119 442.
 *
 * @see <a href="https://docbox.etsi.org/esi/open/Latest_Drafts/ESI-0019442v005.pdf">ETSI TS 119
 * 442</a>
 */
public abstract class ResultException extends Exception {

  private final ResultMajor resultMajor;
  private final ResultMinor resultMinor;

  public ResultException(final String message, final ResultMajor resultMajor,
      final ResultMinor resultMinor) {
    super(message);
    this.resultMajor = resultMajor;
    this.resultMinor = resultMinor;
  }

  public ResultException(final Throwable cause, final ResultMajor resultMajor,
      final ResultMinor resultMinor) {
    super(cause);
    this.resultMajor = resultMajor;
    this.resultMinor = resultMinor;
  }

  public ResultException(final String message, final Throwable cause, final ResultMajor resultMajor,
      final ResultMinor resultMinor) {
    super(message, cause);
    this.resultMajor = resultMajor;
    this.resultMinor = resultMinor;
  }

  public ResultMajor getResultMajor() {
    return resultMajor;
  }

  public ResultMinor getResultMinor() {
    return resultMinor;
  }

}
