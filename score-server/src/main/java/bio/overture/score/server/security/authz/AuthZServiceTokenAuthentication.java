package bio.overture.score.server.security.authz;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuthZServiceTokenAuthentication extends AbstractAuthenticationToken {

  private final AuthZServiceTokenCredentials credentials;

  public AuthZServiceTokenAuthentication(
      AuthZServiceTokenCredentials authZServiceTokenCredentials,
      Collection<GrantedAuthority> authorities) {
    super(authorities);
    this.setAuthenticated(true);

    this.credentials = authZServiceTokenCredentials;
  }

  /**
   * @return serviceToken - Secret token used to authenticate the requesting service.
   */
  @Override
  public Object getCredentials() {
    return credentials.getServiceToken();
  }

  /**
   * @return serviceID - ID of the authenticated service.
   */
  @Override
  public Object getPrincipal() {
    return credentials.getServiceId();
  }
}
