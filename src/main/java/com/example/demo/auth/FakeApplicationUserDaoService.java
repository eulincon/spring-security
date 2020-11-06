package com.example.demo.auth;

import static com.example.demo.security.ApplicationUserRole.STUDENT;
import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.ADMINTRAINEE;

import java.util.List;
import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

import lombok.RequiredArgsConstructor;

@Repository("fake")
@RequiredArgsConstructor
public class FakeApplicationUserDaoService implements ApplicationUserDao{

	private final PasswordEncoder passwordEncoder;
	
	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
			new ApplicationUser(STUDENT.getGrantedAuthorities(), passwordEncoder.encode("password"), "annasmith", true, true, true, true),
			new ApplicationUser(ADMIN.getGrantedAuthorities(), passwordEncoder.encode("password"), "linda", true, true, true, true),
			new ApplicationUser(ADMINTRAINEE.getGrantedAuthorities(), passwordEncoder.encode("password"), "tom", true, true, true, true)
		);
		
		return applicationUsers;
	}

	
}
