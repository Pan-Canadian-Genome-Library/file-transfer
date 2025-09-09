package bio.overture.score.server.security.authz.dto;

import bio.overture.score.server.security.authz.AuthZUserClaims;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthZUserDetailsResponse {

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class UserInfo {

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class UserEmail {

      private String address;
      private String type;
    }

    private List<UserEmail> emails = new ArrayList<>();
    private String pcgl_id;
    private boolean site_curator;
    private boolean site_admin;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class StudyAuthorizations {

    private List<String> editable_studies = new ArrayList<>();
    private List<String> readable_studies = new ArrayList<>();
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class Group {

    private String name;
    private String description;
    private int id;
  }

  private UserInfo userinfo;
  private StudyAuthorizations study_authorizations;
  private List<Group> groups;

  public AuthZUserClaims toClaims() {
    List<String> groupNames =
        this.getGroups().stream()
            .map(AuthZUserDetailsResponse.Group::getName)
            .collect(Collectors.toList());

    return AuthZUserClaims.builder()
        .sub(this.getUserinfo().getPcgl_id())
        .editableStudies(this.getStudy_authorizations().getEditable_studies())
        .readableStudies(this.getStudy_authorizations().getReadable_studies())
        .groups(groupNames)
        .build();
  }
}
