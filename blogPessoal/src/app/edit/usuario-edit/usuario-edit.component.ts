import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { Usuario } from 'src/app/model/Usuario';
import { AlertaService } from 'src/app/service/alerta.service';
import { AuthService } from 'src/app/service/auth.service';
import { environment } from 'src/environments/environment.prod';

@Component({
  selector: 'app-usuario-edit',
  templateUrl: './usuario-edit.component.html',
  styleUrls: ['./usuario-edit.component.css']
})
export class UsuarioEditComponent implements OnInit {

  user: Usuario = new Usuario()
  idUser: number
  confirmSenha: string
  tipoUsuario: string

  constructor(
    private authService: AuthService,
    private route: ActivatedRoute,
    private router: Router,
    private alerta: AlertaService
  ) { }

  ngOnInit() {

    let id = this.route.snapshot.params['id']
    this.findByIdUsuario(id)

    window.scroll(0, 0)

    if (environment.token == "") {
      this.alerta.showAlertInfo("sua sessão expirou")
      this.router.navigate(["/login"])
    }
  }

  findByIdUsuario(id: number) {
    this.authService.getByIdUser(id).subscribe((resp: Usuario) => { this.user = resp })
  }

  confirmaSenha(event: any) {
    this.confirmSenha = event.target.value
  }

  atualizarDados() {
    this.user.tipo = this.tipoUsuario
    if (this.user.senha != this.confirmSenha) {
      this.alerta.showAlertDanger("As senhas não coincidem")
    }
    else {
      this.authService.cadastrar(this.user).subscribe((resp: Usuario) => {
        this.user = resp
        this.alerta.showAlertSuccess("Dados atualizados com sucesso")
        environment.token = ""
        environment.nome = ""
        environment.id = 0
        environment.foto = ""
        this.router.navigate(['/login'])
      })
    }
  }



}
