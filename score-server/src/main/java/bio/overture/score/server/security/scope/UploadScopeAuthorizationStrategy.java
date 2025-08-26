/*
 * Copyright (c) 2019. Ontario Institute for Cancer Research
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package bio.overture.score.server.security.scope;

import bio.overture.score.server.auth.AuthZAuthorizationService;
import bio.overture.score.server.metadata.MetadataService;
import bio.overture.score.server.repository.auth.KeycloakAuthorizationService;
import bio.overture.score.server.util.Scopes;
import java.util.Set;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@Slf4j
public class UploadScopeAuthorizationStrategy extends AbstractScopeAuthorizationStrategy {

  @Autowired private AuthZAuthorizationService authZAuthorizationService;

  @Autowired private KeycloakAuthorizationService keycloakAuthorizationService;

  public UploadScopeAuthorizationStrategy(
      @NonNull String studyPrefix,
      @NonNull String studySuffix,
      @NonNull String systemScope,
      @NonNull MetadataService metadataService,
      @NonNull String provider) {
    super(studyPrefix, studySuffix, systemScope, metadataService, provider);
  }

  public boolean authorize(@NonNull Authentication authentication, @NonNull final String objectId) {
    log.info("Checking upload authorization for objectId {}", objectId);

    String studyId = fetchStudyId(objectId);

    if (studyId == null) {
      log.warn("No study found for objectId {}", objectId);
      return false;
    }

    Set<String> grantedScopes;
    if ("pcglauthz".equalsIgnoreCase(this.getProvider())
        && authentication instanceof BearerTokenAuthentication) {
      return authZAuthorizationService.isAdmin(authentication);
    } else if ("keycloak".equalsIgnoreCase(this.getProvider())
        && authentication instanceof JwtAuthenticationToken) {
      val authGrants =
          keycloakAuthorizationService.fetchAuthorizationGrants(
              ((JwtAuthenticationToken) authentication).getToken().getTokenValue());
      return verifyOneOfSystemScope(extractGrantedScopesFromRpt(authGrants));
    } else {
      return verifyOneOfSystemScope(Scopes.extractGrantedScopes(authentication));
    }
  }
}
