package com.TeachCode.AuthService_TeachCODE.Dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SinginRequest {

    private String email;
    private String password;
}
