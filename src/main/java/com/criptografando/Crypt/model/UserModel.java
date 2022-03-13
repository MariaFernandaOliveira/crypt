package com.criptografando.Crypt.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table (name = "users")
public class UserModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(unique = true)
    private String login;

    //usa essa anotação para não aparecer a senha nas buscas (Segurança)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

}
