package bio.overture.score.server.auth;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;

@Service
@Profile("secure")
public class AuthZAuthorizationService {

  @Value("${authz.admin.group}")
  private String ADMIN_GROUP;

  private Optional<OAuth2AuthenticatedPrincipal> getPrincipalFromAuth(
      Authentication authentication) {
    if (authentication.getPrincipal() instanceof OAuth2AuthenticatedPrincipal) {
      return Optional.ofNullable((OAuth2AuthenticatedPrincipal) authentication.getPrincipal());
    }
    return Optional.empty();
  }

  public boolean isAdmin(AuthZClaims claims) {
    return claims.getGroups().contains(ADMIN_GROUP);
  }

  /**
   * A user can edit a study if they have that study in their `editable_studies` list, or they are
   * an admin
   *
   * @param claims
   * @param studyId
   * @return
   */
  public boolean canEditStudy(AuthZClaims claims, String studyId) {
    return isAdmin(claims) || claims.getEditableStudies().contains(studyId);
  }

  /**
   * A user can edit a study if they have that study in their `readable_studies` list, or they are
   * an admin
   *
   * @param claims
   * @param studyId
   * @return
   */
  public boolean canReadStudy(AuthZClaims claims, String studyId) {
    return isAdmin(claims) || claims.getReadableStudies().contains(studyId);
  }
}
