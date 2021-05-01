package com.example.learning.auth;

import java.util.Optional;

public interface ApplicationUserRepository {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);

}
