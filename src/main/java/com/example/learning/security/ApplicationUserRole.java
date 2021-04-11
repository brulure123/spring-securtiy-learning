package com.example.learning.security;

import lombok.Getter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.example.learning.security.ApplicationUserPermission.*;

@Getter
public enum ApplicationUserRole {

    // TODO: Replace Collections List with Sets for avoiding duplication
    STUDENT(Collections.emptyList()),
    ADMIN(Arrays.asList(
            COURSE_READ,
            COURSE_WRITE,
            STUDENT_READ,
            STUDENT_WRITE
    ));

    private final List<ApplicationUserPermission> permissions;

    ApplicationUserRole(List<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }
}
