import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { Tema } from 'src/app/model/Tema';
import { AlertaService } from 'src/app/service/alerta.service';
import { TemaService } from 'src/app/service/tema.service';
import { environment } from 'src/environments/environment.prod';

@Component({
  selector: 'app-tema-delete',
  templateUrl: './tema-delete.component.html',
  styleUrls: ['./tema-delete.component.css']
})
export class TemaDeleteComponent implements OnInit {

  tema: Tema = new Tema
  idTema: number

  constructor(
    private temaService: TemaService,
    private router: Router,
    private route: ActivatedRoute,
    private alerta: AlertaService
  ) { }

  ngOnInit() {

   this.idTema = this.route.snapshot.params["id"]
    this.findByIdTema(this.idTema)

    if(environment.token == "")
    {
      this.alerta.showAlertInfo("sua sessão expirou")
      this.router.navigate(["/login"])
    }

  }

  findByIdTema(id: number)
  {
    this.temaService.getByIdTema(this.idTema).subscribe((resp: Tema)=>{
      this.tema = resp
    })
  }

    apagar()
    {
      this.temaService.deleteTema(this.idTema).subscribe(()=>{
        this.alerta.showAlertSuccess("Tema excluído com sucesso")
        this.router.navigate(["/tema"])
      })
    }
  }