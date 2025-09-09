package bio.overture.score.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Data
@Profile("pcglauthz")
@Component
@Configuration
@ConfigurationProperties("auth.server.authz")
public class PCGLAuthZConfig {

  private String host;
  private String adminGroup;
  private String serviceName;
  private String serviceToken;
}
