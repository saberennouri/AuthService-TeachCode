package com.TeachCode.AuthService_TeachCODE.Dto.request;

import com.TeachCode.AuthService_TeachCODE.entities.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.Set;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {

    private String name;
    private String email;
    private String phoneNumber;
    private String address;
    private Date dateOfBirth;
    private String password;
    private Set<Role> roles;
}
