import { Component, OnInit } from '@angular/core';
import { environment } from 'src/environments/environment.prod';

@Component({
  selector: 'app-menu',
  templateUrl: './menu.component.html',
  styleUrls: ['./menu.component.css']
})
export class MenuComponent implements OnInit {

  nome = environment.nome
  foto = environment.foto
  id = environment.id

  constructor() { }

  ngOnInit(): void {
  }

  sair()
  {
    environment.token = ""
    
  }

}
