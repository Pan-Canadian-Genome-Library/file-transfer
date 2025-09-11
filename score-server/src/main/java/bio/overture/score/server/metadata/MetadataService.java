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
package bio.overture.score.server.metadata;

import static com.google.common.base.Preconditions.checkArgument;
import static java.lang.Boolean.TRUE;
import static java.lang.String.format;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

import bio.overture.score.server.config.PCGLAuthZConfig;
import bio.overture.score.server.exception.IdNotFoundException;
import bio.overture.score.server.security.authz.AuthZRestClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.retry.RetryCallback;
import org.springframework.retry.RetryContext;
import org.springframework.retry.listener.RetryListenerSupport;
import org.springframework.retry.policy.SimpleRetryPolicy;
import org.springframework.retry.support.RetryTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class MetadataService {

  @Autowired private final AuthZRestClient authZRestClient;
  @Autowired private PCGLAuthZConfig pcglAuthZConfig;

  private final RetryTemplate retryTemplate = unauthorizedServiceTokenRetryTemplate();
  private final RestTemplate restTemplate = serviceTokenInjectedRestTemplate();

  @Value("${metadata.url}")
  private String metadataUrl;

  private static final String ANALYSIS_STATE = "analysisState";
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  public MetadataService(AuthZRestClient authZRestClient) {
    this.authZRestClient = authZRestClient;
  }

  public MetadataEntity getEntity(@NonNull String id) {
    log.debug("using " + metadataUrl + " for MetaData server");
    try {
      val response =
          retryTemplate.execute(
              context ->
                  restTemplate.getForEntity(metadataUrl + "/entities/" + id, MetadataEntity.class));
      return response.getBody();
    } catch (HttpClientErrorException e) {
      if (e.getStatusCode() == NOT_FOUND) {
        throw new IdNotFoundException(format("Entity %s is not registered on the server.", id));
      }

      log.error("Unexpected response code {} while getting ID {}", e.getStatusCode(), id);

      throw e;
    }
  }

  public String getAnalysisStateForMetadata(@NonNull MetadataEntity metadataEntity) {
    val studyId = getStudyId(metadataEntity);
    val analysisId = getAnalysisId(metadataEntity);
    try {
      return readAnalysisState(studyId, analysisId);
    } catch (HttpClientErrorException e) {
      if (e.getStatusCode() == NOT_FOUND || e.getStatusCode() == BAD_REQUEST) {
        throw new IdNotFoundException(
            format(
                "The analysis '%s' with studyId '%s' is not registered on the metadata server. Message: %s",
                analysisId, studyId, e.getResponseBodyAsString()));
      }
      log.error(
          "Unexpected response code {} while getting AnalysisId {} for StudyId {}",
          e.getStatusCode(),
          analysisId,
          studyId);
      throw e;
    }
  }

  public static String getAnalysisId(MetadataEntity metadataEntity) {
    return metadataEntity.getGnosId();
  }

  private static String getStudyId(MetadataEntity metadataEntity) {
    return metadataEntity.getProjectCode();
  }

  @SneakyThrows
  private String readAnalysisState(@NonNull String studyId, @NonNull String analysisId) {
    val response =
        retryTemplate.execute(
            context -> restTemplate.getForObject(getAnalysis(studyId, analysisId), String.class));
    val jsonResponse = OBJECT_MAPPER.readTree(response);
    return parseAnalysisState(jsonResponse);
  }

  private String getAnalysis(String studyId, String analysisId) {
    return format("%s/studies/%s/analysis/%s", metadataUrl, studyId, analysisId);
  }

  private static String parseAnalysisState(JsonNode response) {
    checkArgument(
        response.has(ANALYSIS_STATE),
        "Could not parse '%s' from SONG server response: %s",
        ANALYSIS_STATE,
        response.textValue());
    return response.path(ANALYSIS_STATE).textValue();
  }

  /**
   * This custom RetryListener is added to the StorageClientAuthZConfig retryTemplate. It listens
   * for any failures that are caused by an Unauthorized error from the rest template, when those
   * occur we can clear the stored service token so that the retry attempt will be forced to fetch a
   * fresh token.
   */
  public class ResetUnauthorizedTokenRetryListener extends RetryListenerSupport {

    @Override
    public <T, E extends Throwable> void onError(
        RetryContext context, RetryCallback<T, E> callback, Throwable throwable) {
      log.info("RetryTemplate onError");
      if (throwable instanceof HttpClientErrorException) {
        HttpClientErrorException clientError = (HttpClientErrorException) throwable;

        if (clientError.getStatusCode() == HttpStatus.UNAUTHORIZED) {
          // Service Token failed verification by File-Transfer (Storage Service)
          // Clear the token so a new one will be fetched to build the retry request
          authZRestClient.clearServiceVerificationToken();
        } else {
          // Other ClientErrorExceptions indicate our request is malformed and should not
          // be retried
          context.setExhaustedOnly();
        }
      }
    }
  }

  private RetryTemplate unauthorizedServiceTokenRetryTemplate() {
    final int maxRetries = 2;

    val retryTemplate = new RetryTemplate();

    // Retry all the default retryable exceptions, plus also
    // HttpClientErrorExceptions which include UNAUTHORIZED
    Map<Class<? extends Throwable>, Boolean> retryableExceptions =
        ImmutableMap.<Class<? extends Throwable>, Boolean>builder()
            .put(HttpClientErrorException.class, TRUE)
            .build();
    retryTemplate.setRetryPolicy(new SimpleRetryPolicy(maxRetries, retryableExceptions, true));

    // This custom listener resets the service verification token if the request is
    // rejected as UNAUTHORIZED
    retryTemplate.registerListener(new ResetUnauthorizedTokenRetryListener());

    return retryTemplate;
  }

  private RestTemplate serviceTokenInjectedRestTemplate() {

    val restTemplate = new RestTemplate();

    ClientHttpRequestInterceptor accessTokenAuthIntercept =
        (request, body, clientHttpRequestExecution) -> {
          request
              .getHeaders()
              .add("X-Service-Token", authZRestClient.getServiceVerificationToken());

          request.getHeaders().add("X-Service-Id", pcglAuthZConfig.getServiceId());

          return clientHttpRequestExecution.execute(request, body);
        };

    restTemplate.getInterceptors().add(accessTokenAuthIntercept);

    return restTemplate;
  }
}
