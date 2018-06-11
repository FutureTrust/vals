package eu.futuretrust.vals.protocol.helpers;

import eu.futuretrust.vals.protocol.helpers.exceptions.MarshallerSingletonException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

public class MarshallerSingleton {

  private static JAXBContext context;

  public MarshallerSingleton() {
    try {
      context = JAXBContext.newInstance(
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
    } catch (JAXBException e) {
      e.printStackTrace();
    }
  }

  /**
   * Returns a Unmarshaller intended to unmarshal Objects
   *
   * @param type type of the object
   */
  public <T> Unmarshaller getUnmarshaller(Class<T> type)
      throws JAXBException {
//    JAXBContext context = JAXBContext.newInstance(jaxbContext, type.getClassLoader());
    return context.createUnmarshaller();
  }

  public Unmarshaller getUnmarshaller() throws JAXBException {
    //JAXBContext context = JAXBContext.newInstance(jaxbContext);
    return context.createUnmarshaller();
  }


  public Marshaller getMarshaller(Class type) throws MarshallerSingletonException {
    Marshaller marshaller;
    try {
      //JAXBContext context = JAXBContext.newInstance(jaxbContext, type.getClassLoader());
      marshaller = context.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
      marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
      marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
    } catch (JAXBException e) {
      throw new MarshallerSingletonException(
          "Error during marshalling of type " + type.getCanonicalName());
    }
    return marshaller;
  }
}