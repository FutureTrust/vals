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

package eu.futuretrust.vals.jaxb.adapter;

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class Base64Adapter extends XmlAdapter<String, byte[]>
{
  public byte[] unmarshal(String value) {
    if (value == null) {
      // empty array to prevent NPE
      return new byte[0];
    }
    return value.getBytes();
  }

  public String marshal(byte[] value) {
    if (value == null) {
      return null;
    }
    return new String(value);
  }
}
