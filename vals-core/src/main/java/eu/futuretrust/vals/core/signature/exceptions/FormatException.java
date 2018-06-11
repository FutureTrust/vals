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

package eu.futuretrust.vals.core.signature.exceptions;

public class FormatException extends Exception {

  /**
   * Constructs a new exception with {@code null} as its detail message. The cause is not
   * initialized, and may subsequently be initialized by a call to {@link #initCause}.
   */
  public FormatException() {
    super();
  }

  /**
   * Constructs a new exception with the specified detail message.  The cause is not initialized,
   * and may subsequently be initialized by a call to {@link #initCause}.
   *
   * @param message the detail message. The detail message is saved for later retrieval by the
   * {@link #getMessage()} method.
   */
  public FormatException(String message) {
    super(message);
  }

  /**
   * Constructs a new exception with the specified detail message and cause.  <p>Note that the
   * detail message associated with {@code cause} is <i>not</i> automatically incorporated in this
   * exception's detail message.
   *
   * @param message the detail message (which is saved for later retrieval by the {@link
   * #getMessage()} method).
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   * (A <tt>null</tt> value is permitted, and indicates that the cause is nonexistent or unknown.)
   * @since 1.4
   */
  public FormatException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Constructs a new exception with the specified cause and a detail message of <tt>(cause==null ?
   * null : cause.toString())</tt> (which typically contains the class and detail message of
   * <tt>cause</tt>). This constructor is useful for exceptions that are little more than wrappers
   * for other throwables (for example, {@link java.security.PrivilegedActionException}).
   *
   * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method).
   * (A <tt>null</tt> value is permitted, and indicates that the cause is nonexistent or unknown.)
   * @since 1.4
   */
  public FormatException(Throwable cause) {
    super(cause);
  }

}

