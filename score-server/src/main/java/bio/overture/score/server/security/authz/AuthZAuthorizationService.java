package bio.overture.score.server.security.authz;

import org.springframework.stereotype.Service;

@Service
public class AuthZAuthorizationService {

  /**
   * Determine from AuthZUserClaims if a user is an admin.
   *
   * @param claims
   * @return
   */
  public boolean isAdmin(AuthZUserClaims claims) {
    return claims.isDataAdmin();
  }

  /**
   * A user can edit a study if they have that study in their `editable_studies` list, or they are
   * an admin
   *
   * @param claims
   * @param studyId
   * @return
   */
  public boolean canEditStudy(AuthZUserClaims claims, String studyId) {
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
  public boolean canReadStudy(AuthZUserClaims claims, String studyId) {
    return isAdmin(claims) || claims.getReadableStudies().contains(studyId);
  }
}
