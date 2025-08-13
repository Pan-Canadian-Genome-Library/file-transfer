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
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

@Slf4j
public class UploadScopeAuthorizationStrategy extends AbstractScopeAuthorizationStrategy {

  private final AuthZAuthorizationService authZAuthorizationService;

  public UploadScopeAuthorizationStrategy(
      @NonNull String studyPrefix,
      @NonNull String studySuffix,
      @NonNull String systemScope,
      @NonNull MetadataService metadataService,
      @NonNull String provider,
      @NonNull AuthZAuthorizationService authZAuthorizationService) {
    super(studyPrefix, studySuffix, systemScope, metadataService, provider);
    this.authZAuthorizationService = authZAuthorizationService;
  }

  public boolean authorize(@NonNull Authentication authentication, @NonNull final String objectId) {
    log.info("Checking upload authorization for objectId {}", objectId);

    String studyId = fetchStudyId(objectId);

    if (studyId == null) {
      log.warn("No study found for objectId {}", objectId);
      return false;
    }

    boolean isAuthorized =
        authZAuthorizationService.isAdmin(authentication)
            || authZAuthorizationService.canEditStudy(authentication, studyId);

    if (isAuthorized) {
      log.info(
          "Authorization granted for user {} to upload to study {}",
          authentication.getName(),
          studyId);
    } else {
      log.info(
          "Authorization denied for user {} to upload to study {}",
          authentication.getName(),
          studyId);
    }

    return isAuthorized;
  }
}
