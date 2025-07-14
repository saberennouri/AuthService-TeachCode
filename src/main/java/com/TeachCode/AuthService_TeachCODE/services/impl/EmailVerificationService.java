package com.TeachCode.AuthService_TeachCODE.services.impl;

import com.TeachCode.AuthService_TeachCODE.entities.User;
import com.TeachCode.AuthService_TeachCODE.repositories.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationService {

    private final JavaMailSender mailSender;
    private final UserRepository userRepository;

    @Value("${app.verification-url}")
    private String verificationUrl;

    private void validateEmail(String email) throws AddressException {
        if (email == null || email.isBlank()) {
            throw new AddressException("Adresse e-mail vide ou null");
        }
        InternetAddress internetAddress = new InternetAddress(email);
        internetAddress.validate();
    }

    public void sendVerificationEmail(User user, String verificationLink) {
        try {
            validateEmail(user.getEmail());

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(user.getEmail());
            helper.setSubject("Account verification");

            String emailContent = "<html><body>" +
                    "<h1>Welcome to Our Service!</h1>" +
                    "<p>Please click the following link to verify your account:</p>" +
                    "<a href=\"" + verificationLink + "\">Verify Account</a>" +
                    "<p>Or copy this url to your browser : <br>" +
                    verificationLink + "</p>" +
                    "</body></html>";

            helper.setText(emailContent, true);
            mailSender.send(message);
            log.info("Verification email sent to {}", user.getEmail());
        } catch (AddressException e) {
            log.error("Invalid email address: {}", user.getEmail(), e);
            throw new RuntimeException("Invalid email address", e);
        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}", user.getEmail(), e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    public String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }

    @Transactional
    public boolean verifyUser(String token) {
        log.info("Attempting to verify token: {}", token);

        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> {
                    log.error("Invalid token: {}", token);
                    return new RuntimeException("Invalid verification token");
                });

        if (user.getVerificationTokenExpiry() == null) {
            log.error("No expiry date for token: {}", token);
            throw new RuntimeException("Invalid verification token");
        }

        if (user.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            log.error("Expired token for user: {}", user.getEmail());
            throw new RuntimeException("Verification link has expired");
        }

        if (user.isVerified()) {
            log.warn("User {} already verified", user.getEmail());
            throw new RuntimeException("Account already verified");
        }

        log.info("Verifying user: {}", user.getEmail());
        user.setVerified(true);
        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);
        userRepository.save(user);

        log.info("Successfully verified user: {}", user.getEmail());
        return true;
    }

    public void resendVerificationEmail(User user) {
        String verificationLink = verificationUrl + "?token=" + user.getVerificationToken();

        try {
            validateEmail(user.getEmail());

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(user.getEmail());
            helper.setSubject("Account verification - New Link");

            String emailContent = "<html><body>" +
                    "<h1>New Verification Link!</h1>" +
                    "<p>Here's your verification link:</p>" +
                    "<a href=\"" + verificationLink + "\">Verify Account</a>" +
                    "<p>Or copy this url to your browser : <br>" +
                    verificationLink + "</p>" +
                    "</body></html>";

            helper.setText(emailContent, true);
            mailSender.send(message);
            log.info("Resent verification email to {}", user.getEmail());
        } catch (AddressException e) {
            log.error("Invalid email address: {}", user.getEmail(), e);
            throw new RuntimeException("Invalid email address", e);
        } catch (MessagingException e) {
            log.error("Failed to resend verification email to {}", user.getEmail(), e);
            throw new RuntimeException("Failed to resend verification email", e);
        }
    }
}
