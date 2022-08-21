package com.armaan.springsecuritydemo.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.armaan.springsecuritydemo.security.ApplicationUserPermission.*; // For COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()), // As Student have no roles; Sets coming from google.guava
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
