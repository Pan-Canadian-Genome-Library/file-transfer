package bio.overture.score.server.security.authz;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@Profile("pcglauthz")
public class AuthZAuthenticationFilter extends OncePerRequestFilter {

  @Autowired private AuthZRestClient authZRestClient;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException {
    String serviceToken = request.getHeader("X-Service-Token");
    String serviceId = request.getHeader("X-Service-Id");
    String authorizationHeader = request.getHeader("Authorization");

    if (serviceToken != null && serviceId != null) {
        // Service Token Headers both have a value.
        // Treat this request as coming from another service,
        // using a Service Verification Token to authorize the request.

      val credentials = new AuthZServiceTokenCredentials(serviceId, serviceToken);

      val serviceTokenAuthentication = getServiceTokenAuthentication(credentials);
      if (serviceTokenAuthentication.isPresent()) {

        val authentication = serviceTokenAuthentication.get();
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } else {
        resolveUnauthorized(response);
        return;
      }
    } else if (authorizationHeader != null) {
        // Request has an Authorization header.
        // Treat this request as coming from a user, check for a Bearer token to authorize the request.

      if (!authorizationHeader.startsWith("Bearer ")) {
        resolveUnauthorized(response);
        return;
      }

      String bearerToken = authorizationHeader.substring(7);
      val userTokenAuthentication = getUserTokenAuthentication(bearerToken);
      if (userTokenAuthentication.isPresent()) {
        SecurityContextHolder.getContext().setAuthentication(userTokenAuthentication.get());
        filterChain.doFilter(request, response);
      } else {
        resolveUnauthorized(response);
        return;
      }
    } else {
      // No auth information provided
      SecurityContextHolder.clearContext();
    }

    filterChain.doFilter(request, response);
  }

  private void resolveUnauthorized(@NonNull HttpServletResponse response) throws IOException {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }

  private Optional<AuthZUserTokenAuthentication> getUserTokenAuthentication(
      String authorizationHeader) {
    try {
      Optional<AuthZUserClaims> verifyResponse =
          authZRestClient.verifyUserToken(authorizationHeader);
      if (verifyResponse.isPresent()) {
        val claims = verifyResponse.get();
        val authentication =
            new AuthZUserTokenAuthentication(authorizationHeader, claims, Collections.emptyList());
        return Optional.of(authentication);
      }
      return Optional.empty();
    } catch (Exception e) {
      // Verification failed, log but do not set authentication
      logger.error("Provided service token failed verification request.", e);
      return Optional.empty();
    }
  }

  private Optional<AuthZServiceTokenAuthentication> getServiceTokenAuthentication(
      AuthZServiceTokenCredentials credentials) {
    try {
      boolean isVerified = authZRestClient.verifyServiceToken(credentials);
      if (isVerified) {
        final AuthZServiceTokenAuthentication authentication =
            new AuthZServiceTokenAuthentication(credentials, Collections.emptyList());
        return Optional.of(authentication);
      }
      return Optional.empty();

    } catch (Exception e) {
      // Verification failed, log but do not set authentication
      logger.error("Provided service token failed verification request.", e);
      return Optional.empty();
    }
  }
}
