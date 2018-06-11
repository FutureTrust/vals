package eu.futuretrust.vals.protocol.constants;

public final class SubjectNameInfo {

  private SubjectNameInfo() {}

  public static final String COMMON_NAME = "Ellis Signature Validation";
  public static final String ORGANIZATION = "ARHS Group";
  public static final String COUNTRY = "LU";
  public static final String SUBJECT_NAME = "CN="+ COMMON_NAME +",O=" + ORGANIZATION + ",C="+ COUNTRY;

}
