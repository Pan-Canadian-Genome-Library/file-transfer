package bio.overture.score.server.security.authz;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthZUserClaims {

  private final String sub;
  private final List<String> editableStudies;
  private final List<String> readableStudies;
  private final List<String> groups;
}
