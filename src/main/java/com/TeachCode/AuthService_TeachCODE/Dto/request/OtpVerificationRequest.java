package com.TeachCode.AuthService_TeachCODE.Dto.request;

import lombok.Data;

@Data
public class OtpVerificationRequest {

    private String email;
    private String otp;
}
