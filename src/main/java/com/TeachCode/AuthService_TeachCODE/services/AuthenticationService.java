package com.TeachCode.AuthService_TeachCODE.services;

import com.TeachCode.AuthService_TeachCODE.Dto.request.ResetPasswordRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.SignUpRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.request.SinginRequest;
import com.TeachCode.AuthService_TeachCODE.Dto.response.JwtAuthenticationResponse;
import com.TeachCode.AuthService_TeachCODE.entities.User;

public interface AuthenticationService {


    JwtAuthenticationResponse SignUp(SignUpRequest request);
    JwtAuthenticationResponse SignIn(SinginRequest request);
    void sendForgotPasswordEmail(String email);
    void verifyOTP(String email, String otp);
    void resetPassword(ResetPasswordRequest request);


}
