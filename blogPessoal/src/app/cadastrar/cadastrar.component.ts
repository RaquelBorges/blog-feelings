import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';

import { Usuario } from '../model/Usuario';
import { AlertaService } from '../service/alerta.service';
import { AuthService } from '../service/auth.service';

@Component({
  selector: 'app-cadastrar',
  templateUrl: './cadastrar.component.html',
  styleUrls: ['./cadastrar.component.css']
})
export class CadastrarComponent implements OnInit {

  user: Usuario = new Usuario
  confirmSenha: string
  tipoUser: string

  constructor(
    private authService: AuthService,
    private router: Router,
    private alerta: AlertaService
  ) { }

  ngOnInit() {
  window.scroll(0,0)
  }

  confirmaSenha(event: any)
  {
    this.confirmSenha = event.target.value
  }

  /*tipoUsuario (event: any)
  {
    this.tipoUser = event.target.value
  }*/

  cadastrar ()
  {
    if(this.user.usuario.includes("admin"))
    {
      this.user.tipo = "admin"
    }
    else
    {
      this.user.tipo = "normal"
    }

    if (this.user.senha != this.confirmSenha)
    {
     this.alerta.showAlertDanger("Senhas não coincidem")
    }
    else
    {
      this.authService.cadastrar(this.user).subscribe((resp:Usuario) => {
        this.user = resp
        this.router.navigate(["/login"])
        this.alerta.showAlertSuccess("Usuário cadastrado com sucesso!")
      })
    }
  }
}
