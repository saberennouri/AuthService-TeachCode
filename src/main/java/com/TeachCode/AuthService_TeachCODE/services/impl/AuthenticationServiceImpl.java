package com.TeachCode.AuthService_TeachCODE.services.impl;
import com.TeachCode.AuthService_TeachCODE.Dto.request.ResetPasswordRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.SignUpRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.SinginRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.response.JwtAuthenticationResponse;
import com.TeachCode.AuthService_TeachCODE.Exception.OTPExpiredException;
import com.TeachCode.AuthService_TeachCODE.entities.Role;
import com.TeachCode.AuthService_TeachCODE.entities.User;
import com.TeachCode.AuthService_TeachCODE.repositories.UserRepository;
import com.TeachCode.AuthService_TeachCODE.services.AuthenticationService;
import com.TeachCode.AuthService_TeachCODE.services.JwtService;
import com.TeachCode.AuthService_TeachCODE.services.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.time.LocalDateTime;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

import static com.TeachCode.AuthService_TeachCODE.entities.User.*;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    @Value("${app.verification-url}")
    private String verificationUrl;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationService emailVerificationService;



    @Autowired
    private EmailService emailService;

    @Override
    public JwtAuthenticationResponse SignUp(SignUpRequest request) {
        // Assign default role if no roles are provided
        Set<Role> assignedRoles = request.getRoles() != null ? request.getRoles() : Set.of(Role.STUDENT);

        // Create new User entity
        var user = builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .phoneNumber(request.getPhoneNumber())
                .address(request.getAddress())
                .dateOfBirth(request.getDateOfBirth())
                .roles(assignedRoles)
                .isEnabled(true)
                .isVerified(false)  // Should be false until verified
                .verificationToken(UUID.randomUUID().toString())
                .verificationTokenExpiry(LocalDateTime.now().plusHours(24))  // Expires in 24 hours
                .build();

        // Save user to the database
        userRepository.save(user);
        // Generate verification link and send email
        String verificationLink = verificationUrl + "?token=" + user.getVerificationToken();
        emailVerificationService.sendVerificationEmail(user, verificationLink);

        // Generate JWT & Refresh Token
        var jwt = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.createRefreshToken(user);

        return JwtAuthenticationResponse.builder()
                .token(jwt)
                .refreshToken(refreshToken.getToken())
                .role(assignedRoles.toString()) // Convert Set<Role> to String
                .userId(user.getId())
                .isVerified(user.isVerified())
                .build();
    }

    @Override
    public JwtAuthenticationResponse SignIn(SinginRequest request) {
        // Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        // Fetch user from DB
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));



        // Generate JWT & Refresh Token
        var jwt = jwtService.generateToken(user);
        var refreshToken = refreshTokenService.createRefreshToken(user);

        return JwtAuthenticationResponse.builder()
                .token(jwt)
                .refreshToken(refreshToken.getToken())
                .role(user.getRoles().toString()) // Convert Set<Role> to String
                .userId(user.getId())
                .build();
    }

    public void sendForgotPasswordEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new OTPExpiredException("User with email " + email + " not found"));

        String otp = generateOTP();
        user.setOtp(otp);
        // 💡 Set OTP expiry time to 5 minutes from now
        user.setOtpExpiry(LocalDateTime.now().plusMinutes(5));

        userRepository.save(user);

        emailService.sendOtpEmail(user.getEmail(), otp);
    }

    private String generateOTP() {
        // Generate a random 6-digit OTP
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }

    public void verifyOTP(String email, String otp) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new OTPExpiredException("User with email " + email + " not found"));

        if (!user.getOtp().equals(otp)) {
            throw new OTPExpiredException("Invalid OTP");
        }

        if (user.getOtpExpiry() == null || user.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new OTPExpiredException("OTP has expired");
        }

    }
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new OTPExpiredException("User with email " + request.getEmail() + " not found"));

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }



}

