package eu.futuretrust.vals.protocol.helpers;

import eu.europa.esig.dss.jaxb.diagnostic.XmlContainerInfo;
import eu.europa.esig.dss.jaxb.diagnostic.XmlManifestFile;
import eu.futuretrust.vals.jaxb.commons.ContainerInfoType;
import eu.futuretrust.vals.jaxb.commons.ContainerInfoType.ContentFiles;
import eu.futuretrust.vals.jaxb.commons.ContainerInfoType.ManifestFiles;
import eu.futuretrust.vals.jaxb.commons.ManifestFileType;
import eu.futuretrust.vals.jaxb.commons.ManifestFileType.Entries;
import eu.futuretrust.vals.jaxb.utils.ObjectFactoryUtils;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.collections.CollectionUtils;

public final class ContainerUtils {

  private ContainerUtils() {
  }

  public static ContainerInfoType convert(XmlContainerInfo dssContainerInfo) {
    if (dssContainerInfo == null) {
      return null;
    } else {
      ContainerInfoType containerInfoType = ObjectFactoryUtils.FACTORY_COMMONS
          .createContainerInfoType();

      containerInfoType.setContainerType(dssContainerInfo.getContainerType());
      containerInfoType.setMimeTypeContent(dssContainerInfo.getMimeTypeContent());
      containerInfoType.setMimeTypeFilePresent(dssContainerInfo.isMimeTypeFilePresent());
      containerInfoType.setZipComment(dssContainerInfo.getZipComment());

      if (CollectionUtils.isNotEmpty(dssContainerInfo.getContentFiles())) {
        ContentFiles contentFiles = ObjectFactoryUtils.FACTORY_COMMONS
            .createContainerInfoTypeContentFiles();
        contentFiles.getContentFile().addAll(dssContainerInfo.getContentFiles());
        containerInfoType.setContentFiles(contentFiles);
      }

      if (CollectionUtils.isNotEmpty(dssContainerInfo.getManifestFiles())) {
        ManifestFiles manifestFiles = ObjectFactoryUtils.FACTORY_COMMONS
            .createContainerInfoTypeManifestFiles();
        manifestFiles.getManifestFile().addAll(dssContainerInfo.getManifestFiles().stream()
            .map(ContainerUtils::convert)
            .filter(Objects::nonNull)
            .collect(Collectors.toList()));
        containerInfoType.setManifestFiles(manifestFiles);
      }

      return containerInfoType;
    }
  }

  public static ManifestFileType convert(XmlManifestFile dssManifestFile) {
    if (dssManifestFile == null) {
      return null;
    } else {
      ManifestFileType manifestFileType = ObjectFactoryUtils.FACTORY_COMMONS
          .createManifestFileType();

      manifestFileType.setFilename(dssManifestFile.getFilename());
      manifestFileType.setSignatureFilename(dssManifestFile.getSignatureFilename());

      if (CollectionUtils.isNotEmpty(dssManifestFile.getEntries())) {
        Entries entries = ObjectFactoryUtils.FACTORY_COMMONS
            .createManifestFileTypeEntries();
        entries.getEntry().addAll(dssManifestFile.getEntries());
        manifestFileType.setEntries(entries);
      }

      return manifestFileType;
    }
  }

}
