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

import bio.overture.score.server.auth.AuthZAuthorizationService;
import bio.overture.score.server.exception.NotRetryableException;
import bio.overture.score.server.metadata.MetadataService;
import bio.overture.score.server.security.Access;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.core.Authentication;

@Slf4j
public class DownloadScopeAuthorizationStrategy extends AbstractScopeAuthorizationStrategy {

  private final AuthZAuthorizationService authZAuthorizationService;

  public DownloadScopeAuthorizationStrategy(
      @NonNull String studyPrefix,
      @NonNull String studySuffix,
      @NonNull String systemScope,
      MetadataService metadataService,
      @NonNull String provider,
      @NonNull AuthZAuthorizationService authZAuthorizationService) {
    super(studyPrefix, studySuffix, systemScope, metadataService, provider);
    this.authZAuthorizationService = authZAuthorizationService;
  }

  @Override
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

      String studyId = fetchStudyId(objectId);

      boolean isAdmin = authZAuthorizationService.isAdmin(authentication);
      boolean canWrite = authZAuthorizationService.canEditStudy(authentication, studyId);

      if (isAdmin || canWrite) {
        log.info("User has permission (admin or write access) for study {}", studyId);
        return true;
      } else {
        log.warn("User does NOT have permission for study {}", studyId);
        return false;
      }
    }

    // Step 4: Unexpected access type
    String msg =
        String.format(
            "Invalid access type '%s' found in Metadata record for object id: %s",
            fileAccessType, objectId);
    log.error(msg);
    throw new NotRetryableException(new IllegalArgumentException(msg));
  }
}
