package com.TeachCode.AuthService_TeachCODE.Dto.request;


import lombok.Data;

@Data
public class ResetPasswordRequest {

    private String email;
    private String newPassword;
}
