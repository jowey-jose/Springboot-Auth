package com.example.springbootauth.models;

import javax.persistence.*;
//import javax.validation.constraints.Email;
//import javax.validation.constraints.NotBlank;
//import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(columnNames = "username"),
        @UniqueConstraint(columnNames = "email")
}
)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

//    @NotBlank
//    @Size(max = 20)
    @Column(name = "username")
    private String username;

//    @NotBlank
//    @Size(max = 50)
//    @Email
    @Column(name = "email")
    private String email;

//    @NotBlank
//    @Size(max = 120)
    @Column(name = "password")
    private String password;

    //    Default Constructor
    public User() {
    }

    //    Parameterized Constructor
    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    //    Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
