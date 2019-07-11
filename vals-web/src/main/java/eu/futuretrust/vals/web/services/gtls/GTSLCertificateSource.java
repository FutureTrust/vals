package eu.futuretrust.vals.web.services.gtls;

import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.jaxb.tsl.TSPServiceType;
import eu.futuretrust.vals.web.services.gtls.dto.ResultDTO;
import eu.futuretrust.vals.web.services.helper.ServiceInfoHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.web.client.RestTemplate;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import javax.xml.bind.JAXBElement;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;

public class GTSLCertificateSource extends CommonTrustedCertificateSource {

    private static final Logger LOGGER = LoggerFactory.getLogger(GTSLCertificateSource.class);
    private String gtslEndpointUrl;

    public GTSLCertificateSource(String gtslEndpointUrl) {
        super();
        this.gtslEndpointUrl = gtslEndpointUrl;
    }

    @Override
    protected CertificateSourceType getCertificateSourceType() {
        return CertificateSourceType.TRUSTED_LIST;
    }

    @Override
    public CertificateToken addCertificate(final CertificateToken certificateToken) {
        try {
            BASE64Encoder encoder = new BASE64Encoder();
            String base64Cert = X509Factory.BEGIN_CERT + encoder.encode(certificateToken.getCertificate().getEncoded()) + X509Factory.END_CERT;
            TSPServiceType tspServiceType = fetchGtsl(base64Cert);
            if (tspServiceType != null) {
                ServiceInfo serviceInfo = ServiceInfoHelper.buildServiceInfo(tspServiceType.getServiceInformation(), certificateToken.getCertificate());
                return super.addCertificate(certificateToken, serviceInfo);
            }
        } catch (CertificateEncodingException e) {
            LOGGER.error("Certificate parsing error");
        }
        return null;
    }

    private TSPServiceType fetchGtsl(String base64Cert) {
        RestTemplate restTemplate = new RestTemplate();
        try {
            ResultDTO result = restTemplate.postForObject(gtslEndpointUrl, base64Cert, ResultDTO.class);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream((byte[]) result.getContent());
            JAXBElement<TSPServiceType> jaxbElement = (JAXBElement<TSPServiceType>) tslJaxb2MarshallerV5()
                .unmarshal(new StreamSource(byteArrayInputStream));
            if (jaxbElement.getValue() != null) {
                LOGGER.info(jaxbElement.getValue().getServiceInformation().getServiceStatus());
                return jaxbElement.getValue();
            } else {
                LOGGER.error("Certificate info not available in GTSL");
                return null;
            }
        } catch (Exception e) {
            LOGGER.error("Error fetching GTSL service");
        }
        return null;
    }

    private Jaxb2Marshaller tslJaxb2MarshallerV5() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        Map<String, Object> map = new HashMap<>();
        map.put(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.setMarshallerProperties(map);
        marshaller.setClassesToBeBound(eu.europa.esig.jaxb.tsl.ObjectFactory.class,
            eu.europa.esig.jaxb.xmldsig.ObjectFactory.class);
        return marshaller;
    }
}
