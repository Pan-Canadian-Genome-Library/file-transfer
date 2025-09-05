package bio.overture.score.server.security.authz;

import java.io.IOException;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@Profile("pcglauthz")
public class AuthZServiceTokenAuthenticationFilter extends OncePerRequestFilter {

  @Autowired private AuthZAuthorizationService authZAuthorizationService;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    String serviceToken = request.getHeader("X-Service-Token");
    String serviceId = request.getHeader("X-Service-Id");

    if (serviceToken != null && serviceId != null) {
      AuthZServiceTokenCredentials credentials =
          new AuthZServiceTokenCredentials(serviceId, serviceToken);

      try {
        boolean isVerified = authZAuthorizationService.verifyServiceToken(credentials);
        if (isVerified) {
          final AuthZServiceTokenAuthentication authentication =
              new AuthZServiceTokenAuthentication(credentials, Collections.emptyList());
          SecurityContextHolder.getContext().setAuthentication(authentication);
        }

      } catch (Exception e) {
        // Verification failed, log but do not set authentication
        logger.error("Provided service token failed verification request.", e);
      }
    }

    filterChain.doFilter(request, response);
  }
}
