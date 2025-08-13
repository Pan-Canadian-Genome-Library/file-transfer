package bio.overture.score.server.auth;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Component
@Profile("secure")
public class AuthzTokenIntrospector implements OpaqueTokenIntrospector {

  private final RestTemplate restTemplate = new RestTemplate();

  @Value("${authz.host}")
  private String authzHost;

  @Override
  public OAuth2AuthenticatedPrincipal introspect(String token)
      throws OAuth2AuthenticationException {

    String url = UriComponentsBuilder.fromHttpUrl(authzHost).path("/user/me").toUriString();

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);

    HttpEntity<Void> request = new HttpEntity<>(headers);

    try {
      ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);

      Map<String, Object> userDetails = response.getBody();

      AuthZClaims claims = extractClaims(userDetails);

      Map<String, Object> claimsMap =
          Map.of(
              "sub", claims.getSub(),
              "emails", claims.getEmails(),
              "primary_email", claims.getPrimaryEmail(),
              "editable_studies", claims.getEditableStudies(),
              "readable_studies", claims.getReadableStudies(),
              "groups", claims.getGroups());
      List<GrantedAuthority> authorities = extractAuthorities(claimsMap);
      return new OAuth2IntrospectionAuthenticatedPrincipal(claimsMap, authorities);

    } catch (Exception e) {
      log.error("Failed to introspect token with AuthZ", e);
      throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token"), e.getMessage());
    }
  }

  private AuthZClaims extractClaims(Map<String, Object> userDetails) {
    Map<String, Object> userinfo = (Map<String, Object>) userDetails.get("userinfo");
    Map<String, Object> studyAuths = (Map<String, Object>) userDetails.get("study_authorizations");
    List<Map<String, Object>> groups = (List<Map<String, Object>>) userDetails.get("groups");

    List<Map<String, Object>> emails = (List<Map<String, Object>>) userinfo.get("emails");
    List<Map<String, Object>> safeEmails = (emails != null) ? emails : List.of();

    String primaryEmail =
        safeEmails.stream()
            .filter(e -> "official".equalsIgnoreCase((String) e.get("type")))
            .map(e -> (String) e.get("address"))
            .findFirst()
            .orElseGet(
                () ->
                    safeEmails.stream()
                        .map(e -> (String) e.get("address"))
                        .findFirst()
                        .orElse(null));

    return AuthZClaims.builder()
        .sub((String) userinfo.get("pcgl_id"))
        .emails(safeEmails)
        .primaryEmail(primaryEmail)
        .editableStudies((List<String>) studyAuths.get("editable_studies"))
        .readableStudies((List<String>) studyAuths.get("readable_studies"))
        .groups(groups.stream().map(g -> g.get("name").toString()).collect(Collectors.toList()))
        .build();
  }

  private List<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
    List<String> groups = (List<String>) claims.getOrDefault("groups", List.of());
    return groups.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
  }
}
