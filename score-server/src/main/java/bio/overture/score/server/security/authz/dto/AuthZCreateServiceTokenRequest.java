package bio.overture.score.server.security.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthZCreateServiceTokenRequest {
  private String service_uuid;
}
