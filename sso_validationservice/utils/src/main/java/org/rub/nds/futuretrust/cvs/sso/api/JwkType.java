//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.09.23 at 10:24:46 PM CEST 
//


package org.rub.nds.futuretrust.cvs.sso.api;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for jwkType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="jwkType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="kty" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="sig" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="crv" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="x" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="y" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="alg" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="k" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "jwkType", propOrder = {
    "kty",
    "sig",
    "crv",
    "x",
    "y",
    "alg",
    "k"
})
public class JwkType {

    protected String kty;
    protected String sig;
    protected String crv;
    protected String x;
    protected String y;
    protected String alg;
    protected String k;

    /**
     * Gets the value of the kty property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKty() {
        return kty;
    }

    /**
     * Sets the value of the kty property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKty(String value) {
        this.kty = value;
    }

    /**
     * Gets the value of the sig property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getSig() {
        return sig;
    }

    /**
     * Sets the value of the sig property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setSig(String value) {
        this.sig = value;
    }

    /**
     * Gets the value of the crv property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCrv() {
        return crv;
    }

    /**
     * Sets the value of the crv property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCrv(String value) {
        this.crv = value;
    }

    /**
     * Gets the value of the x property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getX() {
        return x;
    }

    /**
     * Sets the value of the x property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setX(String value) {
        this.x = value;
    }

    /**
     * Gets the value of the y property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getY() {
        return y;
    }

    /**
     * Sets the value of the y property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setY(String value) {
        this.y = value;
    }

    /**
     * Gets the value of the alg property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAlg() {
        return alg;
    }

    /**
     * Sets the value of the alg property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAlg(String value) {
        this.alg = value;
    }

    /**
     * Gets the value of the k property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getK() {
        return k;
    }

    /**
     * Sets the value of the k property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setK(String value) {
        this.k = value;
    }

}
