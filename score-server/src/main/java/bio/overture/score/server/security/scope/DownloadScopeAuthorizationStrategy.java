/*
 * Copyright (c) 2016 The Ontario Institute for Cancer Research. All rights reserved.
 *
 * This program and the accompanying materials are made available under the terms of the GNU Public License v3.0.
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package bio.overture.score.server.security.scope;

import bio.overture.score.server.exception.NotRetryableException;
import bio.overture.score.server.metadata.MetadataService;
import bio.overture.score.server.repository.auth.KeycloakAuthorizationService;
import bio.overture.score.server.security.Access;
import bio.overture.score.server.security.authz.AuthZAuthorizationService;
import bio.overture.score.server.security.authz.AuthZServiceTokenAuthentication;
import bio.overture.score.server.security.authz.AuthZUserTokenIntrospector;
import java.util.Set;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

@Slf4j
public class DownloadScopeAuthorizationStrategy extends AbstractScopeAuthorizationStrategy {

  @Autowired private AuthZAuthorizationService authZAuthorizationService;

  @Autowired private KeycloakAuthorizationService keycloakAuthorizationService;

  public DownloadScopeAuthorizationStrategy(
      @NonNull String studyPrefix,
      @NonNull String studySuffix,
      @NonNull String systemScope,
      MetadataService metadataService,
      @NonNull String provider) {
    super(studyPrefix, studySuffix, systemScope, metadataService, provider);
  }

  public boolean authorize(@NonNull Authentication authentication, @NonNull String objectId) {

    log.info("Checking authorization for objectId {}", objectId);

    val fileAccessType = fetchFileAccessType(objectId);
    val accessType = new Access(fileAccessType);

    if (accessType.isOpen()) {
      log.info("File access is OPEN - granting access");
      return true;
    }

    if (accessType.isControlled()) {
      log.info("File access is CONTROLLED - checking user permissions");

      if ("pcglauthz".equalsIgnoreCase(this.getProvider())) {

        if (authentication instanceof AuthZServiceTokenAuthentication) {
          // Verified service token. Services always have read access.
          return authentication.isAuthenticated();
        }

        String studyId = fetchStudyId(objectId);
        if (studyId == null) {
          log.warn("No study found for objectId {}", objectId);
          return false;
        }
        val claims = AuthZUserTokenIntrospector.extractClaimsFromAuthentication(authentication);

        return claims.isPresent() && authZAuthorizationService.canReadStudy(claims.get(), studyId);
      }

      Set<String> grantedScopes = getGrantedScopes(authentication);
      log.info("Checking system-level authorization for objectId {}", objectId);
      return verifyOneOfSystemScope(grantedScopes)
          || verifyOneOfStudyScope(grantedScopes, objectId);
    } else {
      val msg =
          String.format(
              "Invalid access type '%s' found in Metadata record for object id: %s",
              fileAccessType, objectId);
      log.error(msg);
      throw new NotRetryableException(new IllegalArgumentException(msg));
    }
  }
}
