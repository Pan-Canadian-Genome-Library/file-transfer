package bio.overture.score.server.auth;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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
      ResponseEntity<AuthZUserResponse> response =
          restTemplate.exchange(url, HttpMethod.GET, request, AuthZUserResponse.class);

      AuthZUserResponse userDetails = response.getBody();

      AuthZClaims claims = convertUserResponseToClaims(userDetails);

      Map<String, Object> claimsMap = Map.of("authzClaims", claims);
      return new OAuth2IntrospectionAuthenticatedPrincipal(
          claimsMap, List.of(new SimpleGrantedAuthority("user")));

    } catch (Exception e) {
      log.error("Failed to introspect token with AuthZ", e);
      throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token"), e.getMessage());
    }
  }

  public static Optional<AuthZClaims> extractClaimsFromAuthentication(
      Authentication authentication) {
    val principal = authentication.getPrincipal();
    if (!(principal instanceof OAuth2AuthenticatedPrincipal)) {
      return Optional.empty();
    }
    val claims = ((OAuth2AuthenticatedPrincipal) principal).getAttribute("authzClaims");

    if (!(claims instanceof AuthZClaims)) {
      return Optional.empty();
    }

    return Optional.of((AuthZClaims) claims);
  }

  private AuthZClaims convertUserResponseToClaims(AuthZUserResponse userResponse) {

    List<String> groupNames =
        userResponse.getGroups().stream()
            .map(group -> group.getName())
            .collect(Collectors.toList());

    return AuthZClaims.builder()
        .sub(userResponse.getUserinfo().getPcgl_id())
        .editableStudies(userResponse.getStudy_authorizations().getEditable_studies())
        .readableStudies(userResponse.getStudy_authorizations().getReadable_studies())
        .groups(groupNames)
        .build();
  }
}
