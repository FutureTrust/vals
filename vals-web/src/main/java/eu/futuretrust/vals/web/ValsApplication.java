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

package eu.futuretrust.vals.web;

import eu.futuretrust.vals.jaxb.adapter.Base64Adapter;
import eu.futuretrust.vals.web.configuration.DefaultNamespacePrefixMapper;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;

@SpringBootApplication
public class ValsApplication {

  public static void main(final String[] args) {
    org.apache.xml.security.Init.init();
    SpringApplication.run(ValsApplication.class, args);
  }

  @Bean
  @Qualifier(value = "jaxbBean")
  public Jaxb2Marshaller tslJaxb2MarshallerV5() {
    Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
    marshaller.setAdapters(new Base64Adapter());
    Map<String, Object> map = new HashMap<>();
    map.put(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, true);
    map.put("com.sun.xml.bind.namespacePrefixMapper", new DefaultNamespacePrefixMapper());
    marshaller.setMarshallerProperties(map);
    marshaller.setClassesToBeBound(
        eu.futuretrust.vals.jaxb.commons.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.etsi.esi.tsl.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.etsi.esi.validation.protocol.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.etsi.esi.validation.report.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.etsi.esi.xades.v141.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.dss.core.v1.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.dss.core.v2.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.dss.profiles.ades.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.dss.profiles.asynchronous.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.dss.profiles.dssx.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.dss.profiles.timestamp.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.saml.v1.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.saml.v2.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.oasis.xmldsig.core.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.signvalpol.ObjectFactory.class,
        eu.futuretrust.vals.jaxb.xenc.ObjectFactory.class);
    return marshaller;
  }
}
