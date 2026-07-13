import { NgModule } from '@angular/core';
import { SPNAccountDetailsComponent } from '../spn-account-details';
import { SPNLoginComponent } from '../spn-login';

@NgModule({
  imports: [
    SPNAccountDetailsComponent,
    SPNLoginComponent,
  ],
  exports: [
    SPNAccountDetailsComponent,
    SPNLoginComponent,
  ],
})
export class SPNAccountModule { }
