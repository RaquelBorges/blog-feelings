package com.exercicio.exercicio.service;

import java.nio.charset.Charset;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.apache.commons.codec.binary.Base64;
import com.exercicio.exercicio.model.UserLogin;
import com.exercicio.exercicio.model.Usuario;
import com.exercicio.exercicio.repository.UsuarioRepository;

@Service
public class UsuarioService {
	
	@Autowired
	private UsuarioRepository repository;
	
    public Optional<Usuario> findById(Long id) {
        return repository.findById(id);
    }
	
	public Usuario cadastrarUsuario (Usuario usuario)
	{
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String senhaEnconder = encoder.encode(usuario.getSenha());
		usuario.setSenha(senhaEnconder);
		return repository.save(usuario);
	}
	
	public Optional<UserLogin> Logar (Optional<UserLogin> user)
	{
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		Optional<Usuario> usuario = repository.findByUsuario(user.get().getUsuario());
		
		if(usuario.isPresent()) 
		{
			if(encoder.matches(user.get().getSenha(), usuario.get().getSenha()))
			{
				String auth = user.get().getUsuario() + ":" + user.get().getSenha();
				byte[] encodeAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("US-ASCII")));
				String authHeader = "Basic " + new String(encodeAuth);
				
				user.get().setToken(authHeader);
				user.get().setId(usuario.get().getId());
				user.get().setNome(usuario.get().getNome());
				user.get().setFoto(usuario.get().getFoto());
				user.get().setTipo(usuario.get().getTipo());
				return user;
			}
		}
		return null;
	}

}
