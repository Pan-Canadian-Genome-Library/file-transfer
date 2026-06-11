package bio.overture.score.server.config;

import javax.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Data
@Configuration
@ConfigurationProperties("auth.server.authz")
@Validated
public class PCGLAuthZConfig {

  @NotNull private String host;

  @NotNull private String serviceId;

  @NotNull private String serviceUUID;
}
