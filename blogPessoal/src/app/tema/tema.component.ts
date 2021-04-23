import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { environment } from 'src/environments/environment.prod';
import { Tema } from '../model/Tema';
import { AlertaService } from '../service/alerta.service';
import { TemaService } from '../service/tema.service';

@Component({
  selector: 'app-tema',
  templateUrl: './tema.component.html',
  styleUrls: ['./tema.component.css']
})
export class TemaComponent implements OnInit {

  tema: Tema = new Tema()
  listaTemas: Tema[]
  tipo = environment.tipo
  admin = "admin"

  constructor(
    private router: Router,
    private temaService : TemaService,
    private route: ActivatedRoute,
    private alerta: AlertaService
  ) { }

  ngOnInit() {
    
    this.findAllTema()

    if(environment.token == "")
    {
      this.alerta.showAlertInfo("sua sessão expirou")
      this.router.navigate(["/login"])
    }
    if(environment.tipo != "admin")
    {
      this.alerta.showAlertInfo("Você precisa ser administrador para acessar essa rota")
      this.router.navigate(['/home'])
    }
  }

  findAllTema()
  {
    this.temaService.getAllTema().subscribe((resp: Tema[])=> {
      this.listaTemas = resp
    })
  }

  cadastrarTema()
  {
    this.temaService.postTema(this.tema).subscribe((resp: Tema)=> {
      this.tema = resp
      this.alerta.showAlertSuccess("Tema cadastrado com sucesso")
      this.tema = new Tema()
      this.findAllTema()
    })
  }
 
}
