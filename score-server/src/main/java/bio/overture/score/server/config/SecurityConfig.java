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
package bio.overture.score.server.config;

import bio.overture.score.server.auth.AuthzTokenIntrospector;
import bio.overture.score.server.metadata.MetadataService;
import bio.overture.score.server.properties.ScopeProperties;
import bio.overture.score.server.security.ApiKeyIntrospector;
import bio.overture.score.server.security.scope.DownloadScopeAuthorizationStrategy;
import bio.overture.score.server.security.scope.UploadScopeAuthorizationStrategy;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource service configuration file.<br>
 * Protects resources with access token obtained at the authorization server.
 */
@Slf4j
@Configuration
@Profile("secure")
@EnableWebSecurity
@Getter
@Setter
@ConfigurationProperties("auth.server")
public class SecurityConfig {

  private String url;
  private String clientId;
  private String clientSecret;
  private String provider;
  private String tokenName;

  private final ScopeProperties scopeProperties;

  @Autowired private JwtDecoder jwtDecoder;

  @Autowired private AuthzTokenIntrospector authzTokenIntrospector;

  @Autowired private SwaggerConfig swaggerConfig;

  @Autowired
  public SecurityConfig(@NonNull ScopeProperties scopeProperties) {
    this.scopeProperties = scopeProperties;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf().disable();
    http.authorizeHttpRequests(
            authorize ->
                authorize
                    .antMatchers("/isAlive")
                    .permitAll()
                    .antMatchers("/studies/**")
                    .permitAll()
                    .antMatchers("/upload/**")
                    .permitAll()
                    .antMatchers("/entities/**")
                    .permitAll()
                    .antMatchers("/export/**")
                    .permitAll()
                    .antMatchers("/schemas/**")
                    .permitAll()
                    .antMatchers()
                    .permitAll()
                    .antMatchers(
                        swaggerConfig.getAlternateSwaggerUrl(),
                        "/swagger**",
                        "/swagger-ui.html",
                        "/swagger-ui**",
                        "/swagger-resources/**",
                        "/v2/api-docs/**",
                        "/webjars/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .oauth2ResourceServer(
            oauth2 -> oauth2.authenticationManagerResolver(tokenAuthenticationManagerResolver()));

    return http.build();
  }

  @Bean
  public AuthenticationManagerResolver<HttpServletRequest> tokenAuthenticationManagerResolver() {

    // PCGL AuthZ Provider:
    if (provider.equals("pcglauthz")) {
      return (request) ->
          new ProviderManager(new OpaqueTokenAuthenticationProvider(authzTokenIntrospector));
    }

    // Non PCGL Authz Provider:
    // Auth Managers for JWT and for ApiKeys. JWT uses the default auth provider,
    // but OpaqueTokens are handled by the custom ApiKeyIntrospector
    AuthenticationManager jwt = new ProviderManager(new JwtAuthenticationProvider(jwtDecoder));
    AuthenticationManager opaqueToken =
        new ProviderManager(
            new OpaqueTokenAuthenticationProvider(
                new ApiKeyIntrospector(url, clientId, clientSecret, tokenName)));

    return (request) -> useJwt(request) ? jwt : opaqueToken;
  }

  @Bean
  public UploadScopeAuthorizationStrategy projectSecurity(
      @Autowired MetadataService metadataService) {

    return new UploadScopeAuthorizationStrategy(
        scopeProperties.getUpload().getStudy().getPrefix(),
        scopeProperties.getUpload().getStudy().getSuffix(),
        scopeProperties.getUpload().getSystem(),
        metadataService,
        provider);
  }

  @Bean
  @Scope("prototype")
  public DownloadScopeAuthorizationStrategy accessSecurity(
      @Autowired MetadataService metadataService) {
    return new DownloadScopeAuthorizationStrategy(
        scopeProperties.getDownload().getStudy().getPrefix(),
        scopeProperties.getDownload().getStudy().getSuffix(),
        scopeProperties.getDownload().getSystem(),
        metadataService,
        provider);
  }

  public ScopeProperties getScopeProperties() {
    return this.scopeProperties;
  }

  @Bean
  public OpaqueTokenIntrospector introspector() {
    return new ApiKeyIntrospector(url, clientId, clientSecret, tokenName);
  }

  private boolean useJwt(HttpServletRequest request) {
    val authorizationHeaderValue = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authorizationHeaderValue != null && authorizationHeaderValue.startsWith("Bearer")) {
      String token = authorizationHeaderValue.substring(7);
      try {
        UUID.fromString(token);
        // able to parse as UUID, so this token matches our EgoApiKey format
        return false;
      } catch (IllegalArgumentException e) {
        // unable to parse as UUID, use our JWT resolvers
        return true;
      }
    }
    return true;
  }
}
