package com.exercicio.exercicio.controller;

import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.exercicio.exercicio.model.UserLogin;
import com.exercicio.exercicio.model.Usuario;
import com.exercicio.exercicio.service.UsuarioService;

@RestController 
@CrossOrigin(allowedHeaders = "*", origins = "*")
@RequestMapping("/usuarios")
public class UsuarioController {
	
	@Autowired 
	private UsuarioService usuarioService;
	
	@PostMapping ("/logar")
	public ResponseEntity<UserLogin> autentication (@Valid @RequestBody Optional<UserLogin> user)
	{
		return usuarioService.Logar(user).map(resp -> ResponseEntity.ok(resp))
				.orElse(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
	}
	
	@PostMapping("/cadastrar")
	public ResponseEntity<Usuario> creation (@Valid @RequestBody Usuario usuario)
	{
		return ResponseEntity.status(HttpStatus.CREATED)
				.body(usuarioService.cadastrarUsuario(usuario));
	}
	
	
	@GetMapping("/{id}")
    public ResponseEntity<Usuario> findById(@PathVariable Long id) {
        Optional<Usuario> user = usuarioService.findById(id);
        return user.map(u -> ResponseEntity.status(HttpStatus.OK).body(u))
                .orElse(ResponseEntity.status(HttpStatus.NO_CONTENT).build());
    }
	

}
