package com.TeachCode.AuthService_TeachCODE.services.impl;

import com.TeachCode.AuthService_TeachCODE.repositories.UserRepository;
import com.TeachCode.AuthService_TeachCODE.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;


    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                //.orElseThrow(): C'est une méthode de la classe Optional qui permet de récupérer
                // la valeur contenue dans l'objet Optional. Si la valeur est présente, elle est retournée. Sinon, une exception est levée.
                //Une expression lambda est une fonction anonyme, c'est-à-dire une fonction sans nom,
                // qui peut être utilisée comme un argument ou retournée dans une méthode.
                return userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));

            }
        };
    }
}
