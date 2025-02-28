package com.app.AuthenticationService;

import com.app.AuthenticationService.model.Role;
import com.app.AuthenticationService.model.User;
import com.app.AuthenticationService.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class AuthenticationServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationServiceApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			// Create a Super Administrator user
			if (!userRepository.findByUsername("superadmin").isPresent()) {
				User superAdminUser = new User();
				superAdminUser.setUsername("superadmin");
				superAdminUser.setPassword(passwordEncoder.encode("Super1234")); //  Strong password for Super Admin!
				superAdminUser.setEmail("superadmin@example.com");
				superAdminUser.setFirstname("Super");
				superAdminUser.setLastname("Admin");
				superAdminUser.setRoles(Set.of(Role.SUPER_ADMINISTRATOR)); // Assign SUPER_ADMINISTRATOR role
				userRepository.save(superAdminUser);
			}

			// Create an Admin user
			if (!userRepository.findByUsername("admin").isPresent()) {
				User adminUser = new User();
				adminUser.setUsername("admin");
				adminUser.setPassword(passwordEncoder.encode("password")); // Strong password for Admin!
				adminUser.setEmail("admin@example.com");
				adminUser.setFirstname("Admin");
				adminUser.setLastname("User");
				adminUser.setRoles(Set.of(Role.ADMINISTRATOR)); // Assign ADMIN role
				userRepository.save(adminUser);
			}

			// Create a Teacher user
			if (!userRepository.findByUsername("teacher").isPresent()) {
				User teacherUser = new User();
				teacherUser.setUsername("teacher");
				teacherUser.setPassword(passwordEncoder.encode("password")); // Strong password for Teacher!
				teacherUser.setEmail("teacher@example.com");
				teacherUser.setFirstname("Teacher");
				teacherUser.setLastname("User");
				teacherUser.setRoles(Set.of(Role.TEACHER)); // Assign TEACHER role
				userRepository.save(teacherUser);
			}

			// Create a Student user
			if (!userRepository.findByUsername("student").isPresent()) {
				User studentUser = new User();
				studentUser.setUsername("student");
				studentUser.setPassword(passwordEncoder.encode("password")); // Strong password for Student!
				studentUser.setEmail("student@example.com");
				studentUser.setFirstname("Student");
				studentUser.setLastname("User");
				studentUser.setRoles(Set.of(Role.STUDENT)); // Assign STUDENT role
				userRepository.save(studentUser);
			}
		};
	}

}
//package com.app.AuthenticationService;
//
//import com.app.AuthenticationService.model.Role;
//import com.app.AuthenticationService.model.User;
//import com.app.AuthenticationService.repository.UserRepository;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.boot.SpringApplication;
//import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//import java.util.Set;
//
//@SpringBootApplication
//public class AuthenticationServiceApplication {
//
//	public static void main(String[] args) {
//		SpringApplication.run(AuthenticationServiceApplication.class, args);
//	}
//
//	@Bean
//	public CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder passwordEncoder) {
//		return args -> {
//			// Create an Admin user
//			if (!userRepository.findByUsername("admin").isPresent()) {
//				User adminUser = new User();
//				adminUser.setUsername("admin");
//				adminUser.setPassword(passwordEncoder.encode("password")); // Use a strong password in real app!
//				adminUser.setEmail("admin@example.com");
//				adminUser.setFirstname("Admin");
//				adminUser.setLastname("User");
//				adminUser.setRoles(Set.of(Role.ADMINISTRATOR)); // Assign ADMIN role
//				userRepository.save(adminUser);
//			}
//
//			// Create a Teacher user
//			if (!userRepository.findByUsername("teacher").isPresent()) {
//				User teacherUser = new User();
//				teacherUser.setUsername("teacher");
//				teacherUser.setPassword(passwordEncoder.encode("password"));
//				teacherUser.setEmail("teacher@example.com");
//				teacherUser.setFirstname("Teacher");
//				teacherUser.setLastname("User");
//				teacherUser.setRoles(Set.of(Role.TEACHER)); // Assign TEACHER role
//				userRepository.save(teacherUser);
//			}
//
//			// Create a Student user
//			if (!userRepository.findByUsername("student").isPresent()) {
//				User studentUser = new User();
//				studentUser.setUsername("student");
//				studentUser.setPassword(passwordEncoder.encode("password"));
//				studentUser.setEmail("student@example.com");
//				studentUser.setFirstname("Student");
//				studentUser.setLastname("User");
//				studentUser.setRoles(Set.of(Role.STUDENT)); // Assign STUDENT role
//				userRepository.save(studentUser);
//			}
//		};
//	}
//
//
//	public PasswordEncoder passwordEncoder() { // If you don't already have this in your config
//		return new BCryptPasswordEncoder();
//	}
//}