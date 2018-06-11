package eu.futuretrust.vals.web.configuration;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import org.springframework.boot.jackson.JsonComponent;

@JsonComponent
public class Base64JsonDeserializer extends JsonDeserializer<byte[]> {

  @Override
  public byte[] deserialize(JsonParser parser, DeserializationContext context)
      throws IOException {
    JsonNode node = parser.getCodec().readTree(parser);
    String base64 = node.asText();
    return base64.getBytes();
  }

}
