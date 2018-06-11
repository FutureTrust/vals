package eu.futuretrust.vals.web.configuration;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import org.springframework.boot.jackson.JsonComponent;

@JsonComponent
public class Base64JsonSerializer extends JsonSerializer<byte[]> {

  @Override
  public void serialize(byte[] bytes, JsonGenerator jsonGenerator,
      SerializerProvider serializerProvider) throws IOException {
    jsonGenerator.writeString(new String(bytes));
  }

}

