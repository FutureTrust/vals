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

package eu.futuretrust.vals.jaxb.utils;

public final class ObjectFactoryUtils
{
  private ObjectFactoryUtils() {}

  public static final eu.futuretrust.vals.jaxb.commons.ObjectFactory FACTORY_COMMONS = new eu.futuretrust.vals.jaxb.commons.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.etsi.esi.tsl.ObjectFactory FACTORY_ETSI_02_231 = new eu.futuretrust.vals.jaxb.etsi.esi.tsl.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.ObjectFactory FACTORY_ETSI_119_442 = new eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ObjectFactory FACTORY_ETSI_119_102_2 = new eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.oasis.dss.core.v1.ObjectFactory FACTORY_OASIS_CORE_1 = new eu.futuretrust.vals.jaxb.oasis.dss.core.v1.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ObjectFactory FACTORY_OASIS_CORE_2 = new eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.ObjectFactory FACTORY_OASIS_DSSX = new eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.oasis.saml.v1.ObjectFactory FACTORY_OASIS_SSTC = new eu.futuretrust.vals.jaxb.oasis.saml.v1.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.oasis.saml.v2.ObjectFactory FACTORY_SSTC_2 = new eu.futuretrust.vals.jaxb.oasis.saml.v2.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.ObjectFactory FACTORY_XADES_132 = new eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.xenc.ObjectFactory FACTORY_XENC = new eu.futuretrust.vals.jaxb.xenc.ObjectFactory();
  public static final eu.futuretrust.vals.jaxb.oasis.xmldsig.core.ObjectFactory FACTORY_XML_DSIG = new eu.futuretrust.vals.jaxb.oasis.xmldsig.core.ObjectFactory();
}
