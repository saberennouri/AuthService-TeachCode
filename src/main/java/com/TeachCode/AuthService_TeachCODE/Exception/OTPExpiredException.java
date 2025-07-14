package com.TeachCode.AuthService_TeachCODE.Exception;

public class OTPExpiredException extends RuntimeException {
    public OTPExpiredException(String message) {
        super(message);
    }
}
