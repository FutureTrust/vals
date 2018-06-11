package eu.futuretrust.vals.protocol.helpers;

import java.util.Date;
import java.util.GregorianCalendar;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

public final class XMLGregorianCalendarBuilder {

  private XMLGregorianCalendarBuilder() {
  }

  /**
   * Returns a XMLGregorianCalendar set to the moment specified by {@code date}
   *
   * @param date : an initialized Date
   */
  public static XMLGregorianCalendar createXMLGregorianCalendar(Date date) {
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(date);
    try {
      XMLGregorianCalendar xmlGregorianCalendar =  DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
      xmlGregorianCalendar.setTimezone(0);
      return xmlGregorianCalendar;
    } catch (DatatypeConfigurationException e) {
      // if the gregorian type builder cannot be instantiated; should never happen
    }
    return null;
  }
}
