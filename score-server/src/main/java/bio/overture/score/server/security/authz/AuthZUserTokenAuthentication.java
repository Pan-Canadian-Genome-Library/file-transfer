package bio.overture.score.server.security.authz;

import java.util.Collection;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AuthZUserTokenAuthentication extends AbstractAuthenticationToken {

  private final String bearerToken;

  @Getter
  private final AuthZUserClaims userClaims;

  public AuthZUserTokenAuthentication(
      String bearerToken, AuthZUserClaims userClaims, Collection<GrantedAuthority> authorities) {
    super(authorities);
    this.setAuthenticated(true);

    this.bearerToken = bearerToken;
    this.userClaims = userClaims;
  }

  /**
   * @return serviceToken - Secret token used to authenticate the requesting service.
   */
  @Override
  public Object getCredentials() {
    return this.bearerToken;
  }

  /**
   * @return serviceID - ID of the authenticated service.
   */
  @Override
  public Object getPrincipal() {
    return this.userClaims;
  }

}
