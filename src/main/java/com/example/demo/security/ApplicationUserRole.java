package com.example.demo.security;

import java.util.Set;
import com.google.common.collect.Sets;

import static com.example.demo.security.ApplicationUserPermition.*;

public enum ApplicationUserRole {
	STUDENT(Sets.newHashSet()),	
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
	DFGSDF(Sets.newHashSet(COURSE_READ, STUDENT_READ));
	
	
	private final Set<ApplicationUserPermition> permissions;

	ApplicationUserRole(Set<ApplicationUserPermition> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermition> getPermissions() {
		return permissions;
	}

}
