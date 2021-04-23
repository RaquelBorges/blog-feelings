import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { environment } from 'src/environments/environment.prod';
import { Postagem } from '../model/Postagem';
import { Tema } from '../model/Tema';
import { Usuario } from '../model/Usuario';
import { AlertaService } from '../service/alerta.service';
import { AuthService } from '../service/auth.service';
import { PostagemService } from '../service/postagem.service';
import { TemaService } from '../service/tema.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {

  postagem: Postagem = new Postagem()
  listaTemas: Tema[]
  idTema: number
  tema: Tema = new Tema()
  user: Usuario = new Usuario()
  idUser = environment.id
  listaPostagens: Postagem[]
  key = "data"
  reverse = true
  tituloPost: string
  nomeTema: string
  tipo = environment.tipo
  admin = "admin"
  

  constructor(
    private router: Router,
    private postagemService: PostagemService,
    private temaService: TemaService,
    public authService: AuthService,
    private alerta: AlertaService

  ) { }

  ngOnInit() {

    window.scroll(0, 0)
    this.getAllTemas()
    this.getAllPostagens()

    if (environment.token == "") {
      this.alerta.showAlertInfo("sua sessão expirou")
      this.router.navigate(["/login"])

    }

  }

  getAllTemas() {
    this.temaService.getAllTema().subscribe((resp: Tema[]) => { this.listaTemas = resp })
  }

  findByIdTema() {
    this.temaService.getByIdTema(this.idTema).subscribe((resp: Tema) => { this.tema = resp })
  }

  getAllPostagens() {
    this.postagemService.getAllPostagens().subscribe((resp: Postagem[]) => { this.listaPostagens = resp })
  }

  findByIdUsuario() {
    this.authService.getByIdUser(this.idUser).subscribe((resp: Usuario) => { this.user = resp })
  }

  publicar() {
    this.tema.id = this.idTema
    this.postagem.tema = this.tema

    this.user.id = this.idUser
    this.postagem.usuario = this.user

    this.postagemService.postPostagem(this.postagem).subscribe((resp: Postagem) => { this.postagem = resp })
    this.alerta.showAlertSuccess("Postagem realizada com sucesso")
    this.postagem = new Postagem()

    this.getAllPostagens()
  }

  findByTituloPostagem() {
    if (this.tituloPost == "") {
      this.getAllPostagens()
    }
    else {
      this.postagemService.getByTituloPostagem(this.tituloPost).subscribe((resp: Postagem[]) => {
        this.listaPostagens = resp
      })
    }

  }

  findByNomeTema() {
    if (this.nomeTema == "") {
      this.getAllTemas()
    }
    else {
      this.temaService.getByNomeTema(this.nomeTema).subscribe((resp: Tema[]) => { 
        this.listaTemas = resp 
      })
    }
  }

}
