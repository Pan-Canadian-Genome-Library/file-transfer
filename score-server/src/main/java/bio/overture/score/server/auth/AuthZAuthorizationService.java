package bio.overture.score.server.auth;

import java.util.List;
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

  public boolean isAdmin(Authentication authentication) {
    if (ADMIN_GROUP == null) {
      // ensure that the admin group is configured, don't allow access for admins if
      // this is not configured.
      return false;
    }
    Optional<OAuth2AuthenticatedPrincipal> principalOptional = getPrincipalFromAuth(authentication);
    if (principalOptional.isEmpty()) return false;
    OAuth2AuthenticatedPrincipal principal = principalOptional.get();
    List<String> groups = principal.getAttribute("groups");
    return groups != null && groups.contains(ADMIN_GROUP);
  }

  /**
   * A user can edit a study if they have that study in their `editable_studies` list, or they are
   * an admin
   *
   * @param authentication
   * @param studyId
   * @return
   */
  public boolean canEditStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    Optional<OAuth2AuthenticatedPrincipal> principalOptional = getPrincipalFromAuth(authentication);
    if (principalOptional.isEmpty()) return false;
    OAuth2AuthenticatedPrincipal principal = principalOptional.get();
    List<String> editableStudies = principal.getAttribute("editable_studies");
    return isAdmin(authentication)
        || (editableStudies != null && editableStudies.contains(studyId));
  }

  /**
   * A user can edit a study if they have that study in their `readable_studies` list, or they are
   * an admin
   *
   * @param authentication
   * @param studyId
   * @return
   */
  public boolean canReadStudy(Authentication authentication, String studyId) {
    if (isAdmin(authentication)) return true;
    Optional<OAuth2AuthenticatedPrincipal> principalOptional = getPrincipalFromAuth(authentication);
    if (principalOptional.isEmpty()) return false;
    OAuth2AuthenticatedPrincipal principal = principalOptional.get();
    List<String> readableStudies = principal.getAttribute("readable_studies");
    return isAdmin(authentication)
        || (readableStudies != null && readableStudies.contains(studyId));
  }
}
