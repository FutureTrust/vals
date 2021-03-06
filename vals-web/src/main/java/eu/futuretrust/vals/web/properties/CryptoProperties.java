package eu.futuretrust.vals.web.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("file:${vals.external.crypto.config.path}")
@ConfigurationProperties(prefix = "crypto")
public class CryptoProperties
{
  private String digestAlgorithm;
  private String keystoreType;
  private String keystorePath;
  private String keystorePassword;
  private String trustAnchorCertPath;
  private String signingKeystorePath;
  private String signingKeystorePassword;
  private String tslCachePath;
  private String localKeystorePath;
  private String localKeystorePassword;
  private String crlSourceFolderPath;

  public String getDigestAlgorithm()
  {
    return digestAlgorithm;
  }

  public void setDigestAlgorithm(String digestAlgorithm)
  {
    this.digestAlgorithm = digestAlgorithm;
  }

  public String getKeystoreType()
  {
    return keystoreType;
  }

  public void setKeystoreType(String keystoreType)
  {
    this.keystoreType = keystoreType;
  }

  public String getKeystorePath()
  {
    return keystorePath;
  }

  public void setKeystorePath(String keystorePath)
  {
    this.keystorePath = keystorePath;
  }

  public String getKeystorePassword()
  {
    return keystorePassword;
  }

  public void setKeystorePassword(String keystorePassword)
  {
    this.keystorePassword = keystorePassword;
  }

  public String getTrustAnchorCertPath()
  {
    return trustAnchorCertPath;
  }

  public void setTrustAnchorCertPath(String trustAnchorCertPath)
  {
    this.trustAnchorCertPath = trustAnchorCertPath;
  }

  public String getSigningKeystorePath()
  {
    return signingKeystorePath;
  }

  public void setSigningKeystorePath(String signingKeystorePath)
  {
    this.signingKeystorePath = signingKeystorePath;
  }

  public String getSigningKeystorePassword()
  {
    return signingKeystorePassword;
  }

  public void setSigningKeystorePassword(String signingKeystorePassword)
  {
    this.signingKeystorePassword = signingKeystorePassword;
  }

  public String getTslCachePath()
  {
    return tslCachePath;
  }

  public void setTslCachePath(String tslCachePath)
  {
    this.tslCachePath = tslCachePath;
  }

  public String getLocalKeystorePath() {
    return localKeystorePath;
  }

  public void setLocalKeystorePath(String localKeystorePath) {
    this.localKeystorePath = localKeystorePath;
  }

  public String getLocalKeystorePassword() {
    return localKeystorePassword;
  }

  public void setLocalKeystorePassword(String localKeystorePassword) {
    this.localKeystorePassword = localKeystorePassword;
  }

  public String getCrlSourceFolderPath() {
    return crlSourceFolderPath;
  }

  public void setCrlSourceFolderPath(String crlSourceFolderPath) {
    this.crlSourceFolderPath = crlSourceFolderPath;
  }
}
