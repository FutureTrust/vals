package eu.futuretrust.vals.protocol.enums;

public enum ReportDetailLevel {

  /**
   * Report shall contains all the details
   */
  ALL_DETAILS("urn:oasis:names:tc:dss:1.0:profiles:verificationreport:reportdetail:allDetails");

  private String uri;

  private ReportDetailLevel(String uri) {
    this.uri = uri;
  }

  public String getURI() {
    return this.uri;
  }

}