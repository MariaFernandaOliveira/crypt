package com.criptografando.Crypt.service;


import com.criptografando.Crypt.data.DataUserDetails;
import com.criptografando.Crypt.model.UserModel;
import com.criptografando.Crypt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UserDetailServiceImplement implements UserDetailsService {

    private final UserRepository repository;

    public UserDetailServiceImplement(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserModel> userModelOptional = repository.findByLogin(username);
        if (userModelOptional.isEmpty()){
            throw new UsernameNotFoundException("Username [" + username +"] doesn't exist" );
        }

        return new DataUserDetails(userModelOptional);
    }

    //busca no repository pelo metodo criado pela propria implements, gerando a busca pelo login
}
