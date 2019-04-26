package eu.futuretrust.vals.web.services.report.impl;

import eu.futuretrust.vals.core.enums.SignedObjectFormat;
import eu.futuretrust.vals.jaxb.etsi.esi.xades.v132.DigestAlgAndValueType;
import eu.futuretrust.vals.protocol.exceptions.MessageDigestException;
import eu.futuretrust.vals.protocol.input.SignedObject;
import eu.futuretrust.vals.protocol.output.ValidationReport;
import eu.futuretrust.vals.web.properties.CryptoProperties;
import eu.futuretrust.vals.web.services.report.IndividualReportBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationObjectsBuilderService;
import eu.futuretrust.vals.web.services.report.ValidationReportDataBuilderService;
import eu.futuretrust.vals.web.services.report.XAdESPropertiesMapperService;
import org.assertj.core.api.Assertions;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@RunWith(MockitoJUnitRunner.class)
public class IndividualReportBuilderServiceTest
{
  private CryptoProperties cryptoProperties;
  @Mock
  private ValidationObjectsBuilderService validationObjectsBuilderService;
  @Mock
  private ValidationReportDataBuilderService validationReportDataBuilderService;
  @Mock
  private XAdESPropertiesMapperService xAdESPropertiesMapperService;

  private IndividualReportBuilderService individualReportBuilderService;

  @Before
  public void init() {
    cryptoProperties = new CryptoProperties();
    individualReportBuilderService = new IndividualReportBuilderServiceImpl(cryptoProperties,
            validationObjectsBuilderService,
            validationReportDataBuilderService,
            xAdESPropertiesMapperService);
  }

  @Test
  public void test() throws MessageDigestException {
    cryptoProperties.setDigestAlgorithm("SHA-512");
    DigestAlgAndValueType digestAlgAndValueType = individualReportBuilderService.createDigestAlgAndValue("abcd".getBytes());
    Assertions.assertThat(Base64.decode(digestAlgAndValueType.getDigestValue()).length * 8).isEqualTo(512);
  }

}
