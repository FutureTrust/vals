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

package eu.futuretrust.vals.protocol.input;

import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.core.enums.SignedObjectType;

public class SignedObject
{
  private final byte[] content;
  private final SignedObjectFormat format;
  private final SignedObjectType type;

  public SignedObject(final byte[] content,
                      final SignedObjectFormat format,
                      final SignedObjectType type)
  {
    this.content = content;
    this.format = format;
    this.type = type;
  }

  public byte[] getContent()
  {
    return content;
  }

  public SignedObjectFormat getFormat()
  {
    return format;
  }

  public SignedObjectType getType()
  {
    return type;
  }

}
