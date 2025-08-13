package bio.overture.score.server.auth;

import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthZClaims {
  private final String sub;
  private final List<Map<String, Object>> emails;
  private final String primaryEmail;
  private final List<String> editableStudies;
  private final List<String> readableStudies;
  private final List<String> groups;
}
