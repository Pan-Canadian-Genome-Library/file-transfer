package bio.overture.score.server.security.authz;

import bio.overture.score.server.config.PCGLAuthZConfig;
import bio.overture.score.server.security.authz.dto.AuthZServiceTokenVerificationResponse;
import bio.overture.score.server.security.authz.dto.AuthZUserDetailsResponse;
import java.util.Optional;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
@Profile("pcglauthz")
public class AuthZAuthorizationService {

  @Autowired private PCGLAuthZConfig pcglAuthZConfig;

  private final RestTemplate restTemplate = new RestTemplate();

  public boolean verifyServiceToken(AuthZServiceTokenCredentials credentials)
      throws RestClientException {
    String url =
        UriComponentsBuilder.fromHttpUrl(pcglAuthZConfig.getHost())
            .pathSegment("service")
            .pathSegment(credentials.getServiceId())
            .pathSegment("verify")
            .toUriString();

    HttpHeaders headers = new HttpHeaders();
    headers.set("X-Service-Token", credentials.getServiceToken());

    HttpEntity<Void> request = new HttpEntity<>(headers);

    ResponseEntity<AuthZServiceTokenVerificationResponse> response =
        restTemplate.exchange(
            url, HttpMethod.GET, request, AuthZServiceTokenVerificationResponse.class);

    val body = response.getBody();

    return body != null && body.isResult();
  }

  public Optional<AuthZUserClaims> verifyUserToken(String token) throws RestClientException {
    String url =
        UriComponentsBuilder.fromHttpUrl(pcglAuthZConfig.getHost()).path("/user/me").toUriString();

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);

    HttpEntity<Void> request = new HttpEntity<>(headers);

    ResponseEntity<AuthZUserDetailsResponse> response =
        restTemplate.exchange(url, HttpMethod.GET, request, AuthZUserDetailsResponse.class);

    AuthZUserDetailsResponse userDetails = response.getBody();
    if (userDetails != null) {
      return Optional.of(userDetails.toClaims());
    }
    return Optional.empty();
  }

  /**
   * Determine from AuthZUserClaims if a user is an admin.
   *
   * @param claims
   * @return
   */
  public boolean isAdmin(AuthZUserClaims claims) {
    return claims.getGroups().contains(pcglAuthZConfig.getAdminGroup());
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
