package eu.futuretrust.vals.web.services.helper;

import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.util.MutableTimeDependentValues;
import eu.europa.esig.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.jaxb.tsl.TSPServiceInformationType;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ServiceInfoHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServiceInfoHelper.class);

    private ServiceInfoHelper() {
    }

    //TODO: Add missing serviceInfo details
    public static ServiceInfo buildServiceInfo(TSPServiceInformationType tspServiceInformationType,
                                               X509Certificate certificate) {
        ServiceInfo serviceInfo = new ServiceInfo();

        if (tspServiceInformationType.getServiceName().getName() != null &&
            !tspServiceInformationType.getServiceName().getName().isEmpty()) {
            serviceInfo.setTspName(tspServiceInformationType.getServiceName().getName().get(0).getValue());
        }

        if (tspServiceInformationType.getServiceDigitalIdentity() != null) {
            for (DigitalIdentityType digitalIdentityType : tspServiceInformationType.getServiceDigitalIdentity().getDigitalId()) {
                if (digitalIdentityType.getX509Certificate() != null) {
                    X509Certificate x509Certificate = getX509Certificate(digitalIdentityType.getX509Certificate());
                    String countryName = extractCountryName(x509Certificate);
                    serviceInfo.setTlCountryCode(countryName);
                }
            }
        }

        final MutableTimeDependentValues<ServiceInfoStatus> status = new MutableTimeDependentValues<ServiceInfoStatus>();
        final Map<String, List<Condition>> qualifiersAndConditions = new HashMap<>();
        final ServiceInfoStatus serviceInfoStatus = new ServiceInfoStatus(tspServiceInformationType.getServiceName().getName().get(0).getValue(),
                tspServiceInformationType.getServiceTypeIdentifier(),
                tspServiceInformationType.getServiceStatus(),
                new HashMap<>(), new ArrayList<>(), new ArrayList<>(), null, null, null);

        status.addOldest(serviceInfoStatus);
        serviceInfo.setStatus(status);

        return serviceInfo;
    }

    private static String extractCountryName(X509Certificate certificate) {
        X500Name x500name = null;
        try {
            x500name = new JcaX509CertificateHolder(certificate).getSubject();
        } catch (CertificateEncodingException e) {
            LOGGER.error("Failed getting certificate subject");
            return null;
        }
        RDN[] rdnArray = x500name.getRDNs(BCStyle.C);
        if (rdnArray.length == 0) {
            return null;
        }
        return IETFUtils.valueToString(rdnArray[0].getFirst().getValue());
    }

    private static X509Certificate getX509Certificate(byte[] certificateBytes) {
        if (certificateBytes != null && certificateBytes.length > 0) {
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(certificateBytes);
                return (X509Certificate) certFactory.generateCertificate(in);
            } catch (CertificateException e) {
                LOGGER.error("Failed parsing certificate: ", e);
            }
        }
        return null;
    }
}
