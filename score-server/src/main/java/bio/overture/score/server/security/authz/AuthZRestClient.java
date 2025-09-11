package bio.overture.score.server.security.authz;

import bio.overture.score.server.config.PCGLAuthZConfig;
import bio.overture.score.server.security.authz.dto.AuthZCreateServiceTokenRequest;
import bio.overture.score.server.security.authz.dto.AuthZCreateServiceTokenResponse;
import bio.overture.score.server.security.authz.dto.AuthZServiceTokenVerificationResponse;
import bio.overture.score.server.security.authz.dto.AuthZUserDetailsResponse;
import java.util.Optional;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class AuthZRestClient {

  @Autowired private PCGLAuthZConfig pcglAuthZConfig;

  private final RestTemplate restTemplate = new RestTemplate();

  private Optional<String> serviceVerificationToken = Optional.empty();

  private String sendPostCreateServiceToken() throws RestClientException {
    String url =
        UriComponentsBuilder.fromHttpUrl(pcglAuthZConfig.getHost())
            .pathSegment("service")
            .pathSegment(pcglAuthZConfig.getServiceId())
            .pathSegment("verify")
            .toUriString();

    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

    HttpEntity<AuthZCreateServiceTokenRequest> request =
        new HttpEntity<>(
            new AuthZCreateServiceTokenRequest(pcglAuthZConfig.getServiceUUID()), headers);

    ResponseEntity<AuthZCreateServiceTokenResponse> response =
        restTemplate.exchange(url, HttpMethod.POST, request, AuthZCreateServiceTokenResponse.class);

    val body = response.getBody();

    if (body == null) {
      throw new RestClientException("Failed to retrieve Service Verification Token.");
    }

    return body.getToken();
  }

  /**
   * Makes a request to AuthZ to verify if a user Bearer token is valid, and if so retrieve the
   * user's auth claims.
   *
   * <p>This request requires that it is sent from a Service registered with AuthZ, so we send the
   * serviceVerificationToken as a header to authenticate this request. It can happen that this
   * token has expired, and in that case this request will receive an HTTP Error Response 403
   * FORBIDDEN. In this case, you can retrieve a new service token and retry the request.
   *
   * @return If successful, will return the User's auth claims.
   * @throws RestClientException
   */
  private AuthZUserClaims sendGetVerifyUserToken(String token) throws RestClientException {
    String url =
        UriComponentsBuilder.fromHttpUrl(pcglAuthZConfig.getHost()).path("/user/me").toUriString();

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.set("X-Service-Token", getServiceVerificationToken());
    headers.set("X-Service-Id", pcglAuthZConfig.getServiceId());

    HttpEntity<Void> request = new HttpEntity<>(headers);

    ResponseEntity<AuthZUserDetailsResponse> response =
        restTemplate.exchange(url, HttpMethod.GET, request, AuthZUserDetailsResponse.class);

    AuthZUserDetailsResponse userDetails = response.getBody();
    if (userDetails == null) {
      return null;
    }

    return userDetails.toClaims();
  }

  /**
   * Get the current service verification token, if present. If it is not present, a new token will
   * be fetched from AuthZ.
   *
   * @return
   * @throws RestClientException
   */
  public String getServiceVerificationToken() throws RestClientException {
    if (serviceVerificationToken.isPresent()) {
      return serviceVerificationToken.get();
    }
    serviceVerificationToken = Optional.of(sendPostCreateServiceToken());
    return serviceVerificationToken.get();
  }

  /**
   * Remove the stored Service Verification Token. This should be called when a request made using
   * this token is rejected as unauthorized from the receiving service, or if verifying a User Token
   * using the stored Service Token receives a 403 Forbidden response from AuthZ.
   *
   * @throws RestClientException
   */
  public void clearServiceVerificationToken() throws RestClientException {
    serviceVerificationToken = Optional.empty();
  }

  /**
   * Makes a request to AuthZ to verify if a service token credentials are valid. This should be
   * used when this application receives a Service Token and ID as headers with any request.
   *
   * @param credentials
   * @return true if the provided credentials are valid
   * @throws RestClientException
   */
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

  /**
   * Checks user Bearer token with AuthZ to verify if the user is authenticated and retrieve their
   * Auth claims. This should be used to check Bearer tokens received with incoming requests.
   *
   * @param token
   * @return
   * @throws RestClientException
   */
  public Optional<AuthZUserClaims> verifyUserToken(String token) throws RestClientException {
    try {
      val response = sendGetVerifyUserToken(token);
      return Optional.ofNullable(response);

    } catch (HttpClientErrorException e) {
      if (e.getStatusCode() == HttpStatus.FORBIDDEN) {
        // Handle HTTP 403 Forbidden Response.
        // This response happens when the stored service token has expired, so we clear it and try
        // one additional time
        clearServiceVerificationToken();
        val retryResponse = sendGetVerifyUserToken(token);
        return Optional.ofNullable(retryResponse);
      }
      return Optional.empty();
    }
  }
}
