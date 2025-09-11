package bio.overture.score.server.security.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthZServiceTokenVerificationResponse {

  private boolean result;
}
