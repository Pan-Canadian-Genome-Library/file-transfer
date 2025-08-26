package bio.overture.score.server.auth;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthZUserResponse {

  @Data
  @AllArgsConstructor
  public class UserInfo {

    @Data
    @AllArgsConstructor
    public class UserEmail {

      private final String address;
      private final String type;
    }

    private final List<UserEmail> emails;
    private final String pcgl_id;
  }

  @Data
  @AllArgsConstructor
  public class StudyAuthorizations {

    private final List<String> editable_studies;
    private final List<String> readable_studies;
  }

  @Data
  @AllArgsConstructor
  public class Group {

    private final String name;
    private final String description;
    private final int id;
  }

  private final UserInfo userinfo;
  private final StudyAuthorizations study_authorizations;
  private final List<Group> groups;
}
