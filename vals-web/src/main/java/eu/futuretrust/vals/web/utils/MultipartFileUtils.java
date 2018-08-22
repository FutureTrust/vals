package eu.futuretrust.vals.web.utils;

import eu.futuretrust.vals.protocol.input.documents.InputDocument;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class MultipartFileUtils
{
  public static boolean valid(final MultipartFile file) {
    if (file == null || file.isEmpty()) {
      return false;
    }
    return true;
  }

  public static boolean valid(final MultipartFile[] files) {
    if (files != null && files.length != 0
            && Arrays.stream(files).anyMatch(MultipartFile::isEmpty)) {
      return false;
    }
    return true;
  }

  public static List<InputDocument> toInputDocuments(MultipartFile[] multipartFiles)
          throws IOException
  {
    return toInputDocuments(Arrays.asList(multipartFiles));
  }

  public static List<InputDocument> toInputDocuments(List<MultipartFile> multipartFiles)
          throws IOException {
    if (multipartFiles != null && !multipartFiles.isEmpty()) {
      return getInputDocuments(multipartFiles);
    }
    return new ArrayList<>();
  }

  private static List<InputDocument> getInputDocuments(List<MultipartFile> multipartFiles)
          throws IOException {
    List<InputDocument> inputDocuments = new ArrayList<>();
    for (MultipartFile multipartFile : multipartFiles) {
      String safeName = safeName(multipartFile.getOriginalFilename(), inputDocuments);
      inputDocuments.add(new InputDocument(safeName, multipartFile.getBytes()));
    }
    return inputDocuments;
  }

  public static String safeName(String filename, List<InputDocument> inputDocuments) {
    StringBuilder safeName = new StringBuilder(filename == null ? "unnamed" : filename);

    List<String> conflicts = inputDocuments.stream()
            .filter(doc -> doc.getName() != null
                    && doc.getName().matches("^" + safeName.toString() + "(_\\d)?$"))
            .map(InputDocument::getName)
            .collect(Collectors.toList());
    if (conflicts.isEmpty()) {
      return safeName.toString();
    }

    while (conflicts.contains(safeName.toString())) {
      if (safeName.toString().matches("^.+?_\\d$")) {
        String index = safeName.toString().substring(safeName.toString().lastIndexOf('_') + 1);
        if (StringUtils.isNumeric(index)) {
          Integer i = Integer.parseInt(index);
          safeName.replace(
                  safeName.toString().lastIndexOf('_') + 1,
                  safeName.toString().length(),
                  (++i).toString());
        } else {
          throw new NumberFormatException("Index at the end of the file is not valid");
        }
      } else {
        safeName.append("_1");
      }
    }

    return safeName.toString();
  }
}
